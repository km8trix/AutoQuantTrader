"""Eight fresh C1/I/J/B/current-lease observations; no statement writer.

The real startup C1 retains released S. Current owners and B bind separate R1.
Valid declared J mismatches and R2 expose explicit missing consumer comparisons;
their successful component calls are not production denials or write authority.
"""

import hashlib
import stat
import sys
import threading
from collections import Counter
from contextlib import contextmanager
from dataclasses import fields, is_dataclass, replace
from datetime import timedelta
from decimal import Decimal
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
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_synthetic_session_owners,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import causal_engine
from packages.application import personal_codec as codec
from packages.application.operational_control_operator_journal import (
    operator_statement_journal_append,
    operator_statement_journal_key,
)
from packages.application.operational_control_operator_preparation import (
    PreparedOperationalControlOperatorStatementRecord,
)
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
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_account import ContinuousAccountConflict, SqlContinuousAccount
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured

_OWNER = "account-context-test-operator"
_AUTHORITY = "a" * 64
_PAYLOAD = b"synthetic account-context evidence\x00\xff\n"
_LEASE_TABLES = (
    phase2_account_lease_heads,
    phase2_account_leases,
    phase2_account_lease_releases,
)
_CODES = (
    (LocalOperatorSecurity.authenticate_with_expiry.__code__, "authenticate"),
    (OperatorStatementEvidenceReader.read.__code__, "evidence"),
    (LocalResearchArtifactStore.read.__code__, "read"),
    (LocalResearchArtifactStore.put.__code__, "put"),
    (LocalResearchArtifactStore.install_file.__code__, "install"),
    (codec.encode_record.__code__, "encode"),
    (codec.decode_record.__code__, "decode"),
    (SqlDurableJournal.prepare_append.__code__, "prepare"),
    (SqlDurableJournal.append.__code__, "append"),
    (SqlDurableJournal.append_in_transaction.__code__, "append_in_transaction"),
    (causal_engine.initialize_continuous_engine.__code__, "engine_initialize"),
    (causal_engine.advance_continuous_engine.__code__, "engine_advance"),
    (
        causal_engine.advance_continuous_engine_with_applications.__code__,
        "engine_advance_with_applications",
    ),
    (causal_engine.apply_continuous_runtime_action.__code__, "engine_runtime_action"),
)


class _Context(SimpleNamespace):
    def __repr__(self):
        return "<synthetic account-context qualification>"


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
    files = []
    for path in sorted(root.iterdir()):
        information = path.lstat()
        assert stat.S_ISREG(information.st_mode)
        files.append(
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
    return directory.st_mode, directory.st_uid, directory.st_ino, tuple(files)


def _rows(engine, tables):
    with engine.connect() as connection:
        return {
            table.name: tuple(
                dict(row)
                for row in connection.execute(
                    sa.select(table).order_by(*table.primary_key.columns)
                ).mappings()
            )
            for table in tables
        }


def _inventory(value):
    """Every actual registered table, including empty financial/legacy tables."""
    account, venue = value.ports["account_engine"], value.ports["venue_engine"]
    account_names = tuple(sorted(sa.inspect(account).get_table_names()))
    venue_names = tuple(sorted(sa.inspect(venue).get_table_names()))
    assert account_names == tuple(sorted(metadata.tables))
    assert venue_names == tuple(sorted(table.name for table in JOURNAL_TABLES))
    tables = tuple(metadata.tables[name] for name in account_names)
    schema = tuple(
        (
            table.name,
            tuple(
                (column.name, str(column.type), column.nullable, column.primary_key)
                for column in table.columns
            ),
        )
        for table in tables
    )
    return (
        schema,
        _rows(account, tuple(table for table in tables if table not in _LEASE_TABLES)),
        _rows(venue, JOURNAL_TABLES),
        tuple(
            _artifact_inventory(value.ports[name]._root)
            for name in ("account_artifacts", "venue_artifacts")
        ),
    )


def _track_engine(value, engine, label):
    connections = []

    def connected(connection):
        connections.append(connection)

    def executed(connection, cursor, statement, parameters, context, executemany):
        # Deliberately retain no SQL text, parameters, frames or session payload.
        value.sql.append(label)

    value.engines.append((engine, connections, label))
    for event, listener in (("engine_connect", connected), ("before_cursor_execute", executed)):
        sa.event.listen(engine, event, listener)
        value.listeners.append((engine, event, listener))


@contextmanager
def _observe(value):
    """Observe native code entries; never replace a component success path."""
    monitor = sys.monitoring
    tool = next((number for number in (4, 3, 2, 1, 0) if monitor.get_tool(number) is None), None)
    assert tool is not None and monitor.get_events(tool) == 0
    enabled = []
    owned = registered = False
    primary = None

    def started(code, offset):
        label = next(label for original, label in _CODES if code is original)
        value.entries[label] += 1
        if label in ("put", "install", "append", "append_in_transaction"):
            raise AssertionError("excluded publication after account-context setup")
        if threading.current_thread() is value.final_thread:
            raise AssertionError("auth/file/codec/preparation/replay entered final account scope")

    try:
        monitor.use_tool_id(tool, "aqt-operator-account-context")
        owned = True
        previous = monitor.register_callback(tool, monitor.events.PY_START, started)
        if previous is not None:
            conflict = AssertionError("account-context observer callback slot was not free")
            try:
                assert monitor.register_callback(tool, monitor.events.PY_START, previous) is started
            except BaseException as rollback:
                raise BaseExceptionGroup(
                    "account-context observer collision rollback failed", [conflict, rollback]
                ) from None
            raise conflict
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
                    assert monitor.register_callback(tool, monitor.events.PY_START, None) is started
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                assert monitor.get_tool(tool) == "aqt-operator-account-context"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup(
                "account-context observer cleanup failed", ([primary] if primary else []) + errors
            )


@contextmanager
def _account_interval(value):
    """Only delimit native monitoring; perform no authority or admission check."""
    assert value.final_connection is value.final_thread is None
    value.final_thread = threading.current_thread()
    try:
        yield
    finally:
        value.final_connection = value.final_thread = None


def _graph(value):
    current, ports = value.current, value.ports
    return (
        current.account,
        current.account.engine,
        current.account.coordinator,
        current.account.journal,
        current.account.journal._engine,
        current.account.journal._codec,
        current.account.artifacts,
        current.account.codec,
        current.account.preparer,
        current.account.composer,
        current.account.composer.engine,
        current.account.composer.coordinator,
        current.account.composer.artifacts,
        current.account.composer.codec,
        current.account.composer.forward_sources,
        current.account.composer.accounting,
        current.account.composer.daily,
        current.account.composer.producer_history,
        current.account.composer.venue_sources,
        current.daily,
        current.daily.engine,
        current.daily.coordinator,
        current.daily.producers,
        current.daily.codec,
        current.runtime,
        current.runtime.accounts,
        current.runtime.daily,
        current.venue_sources,
        ports["account_engine"],
        ports["account_artifacts"],
        value.issuer,
        value.issuer.security,
        value.reader,
        value.preparer,
        value.preparer.issuer,
        value.preparer.reader,
        value.preparer.clock,
        value.journal,
        value.journal._engine,
        value.journal._codec,
    )


def _assert_unchanged(value):
    assert _inventory(value) == value.baseline
    assert all(
        actual is original for actual, original in zip(_graph(value), value.graph, strict=True)
    )
    assert value.c.receipt == value.genesis.restored.receipt
    assert value.c.checkpoint == value.genesis.restored.checkpoint
    assert value.c.receipt.fence_reference.lease_sha256 == value.genesis.lease.semantic_sha256
    assert value.raw.receipt.semantic_sha256 == value.raw_receipt_sha256
    assert value.raw.receipt.lease_sha256 == value.r1.semantic_sha256
    assert value.b.raw is value.raw and value.b.control == value.genesis.control
    assert value.b.control.effective_state is OperationalControlState.HALTED
    assert (
        value.current.account.composer.fence
        == value.current.runtime.current_fence()
        == value.r1.fence
    )
    assert not value.genesis.owners.commands.authenticator.security._enabled
    assert not value.genesis.owners.commands.authenticator._owned
    assert value.final_connection is value.final_thread is None
    assert all(
        value.entries[label] == 0 for label in ("put", "install", "append", "append_in_transaction")
    )
    assert all(value.entries[label] == 0 for _, label in _CODES if label.startswith("engine_"))
    rows = _rows(value.ports["account_engine"], (phase2_account_leases,))
    expected = (value.genesis.lease, value.r1)
    if value.latest is not value.r1:
        expected += (value.latest,)
    leases = rows[phase2_account_leases.name]
    assert {account_lease_from_row(row).semantic_sha256 for row in leases} == {
        lease.semantic_sha256 for lease in expected
    }
    assert len(leases) == len(expected)
    assert all(account_lease_from_row(row) in expected for row in leases)


def _finish(value, primary):
    errors = []
    if value.baseline is not None:
        try:
            _assert_unchanged(value)
        except BaseException as error:
            errors.append(error)
    if value.latest is not None:
        coordinator = value.genesis.account.coordinator
        known_current = False
        try:
            # Do not infer release authority for a foreign or unexpected revision.
            assert coordinator.current() == value.latest
            known_current = True
        except BaseException as error:
            errors.append(error)
        head = None
        try:
            before = _rows(value.ports["account_engine"], (phase2_account_lease_heads,))
            head = before[phase2_account_lease_heads.name][0]
            assert head["account_id"] == value.r1.account_id
            assert head["last_fencing_generation"] == value.r1.fencing_generation
            assert head["current_fencing_generation"] == value.r1.fencing_generation
            assert head["current_lease_sha256"] == value.latest.semantic_sha256
            if hasattr(value, "head_before"):
                assert value.head_before["updated_at"] <= head["updated_at"]
                assert head == {
                    **value.head_before,
                    "current_lease_sha256": value.latest.semantic_sha256,
                    "updated_at": head["updated_at"],
                }
            assert head["updated_at"] <= value.ports["clock"].now().replace(tzinfo=None)
            assert value.ports["clock"].now() < value.r1.expires_at
        except BaseException as error:
            errors.append(error)
        if known_current:
            try:
                # One release attempt, including when an independent assertion failed.
                release = coordinator.release(value.latest.fence)
                assert release.fence == value.latest.fence
                assert release.lease_sha256 == value.latest.semantic_sha256
                assert release.policy_sha256 == value.latest.policy_sha256
                assert release.released_at == value.ports["clock"].now()
                assert coordinator.current() is None
                rows = _rows(
                    value.ports["account_engine"],
                    (phase2_account_lease_heads, phase2_account_lease_releases),
                )
                releases = tuple(
                    account_lease_release_from_row(row)
                    for row in rows[phase2_account_lease_releases.name]
                )
                assert len(releases) == 2
                assert value.genesis.release in releases and release in releases
                released_head = rows[phase2_account_lease_heads.name][0]
                if head is not None:
                    assert released_head == {
                        **head,
                        "current_fencing_generation": None,
                        "current_lease_sha256": None,
                        "updated_at": release.released_at.replace(tzinfo=None),
                    }
            except BaseException as error:
                errors.append(error)
    if value.baseline is not None:
        try:
            _assert_unchanged(value)
        except BaseException as error:
            errors.append(error)
    for engine, connections, label in value.engines:
        try:
            assert all(connection.closed for connection in connections)
            if label == "foreign":
                assert sa.inspect(engine).get_table_names() == []
                assert all(connection.closed for connection in connections)
        except BaseException as error:
            errors.append(error)
    for engine, event, listener in reversed(value.listeners):
        try:
            sa.event.remove(engine, event, listener)
            assert not sa.event.contains(engine, event, listener)
        except BaseException as error:
            errors.append(error)
    for engine, connections, label in value.engines:
        if label == "foreign" and all(connection.closed for connection in connections):
            try:
                engine.dispose()
            except BaseException as error:
                errors.append(error)
    if errors:
        raise BaseExceptionGroup(
            "account-context fixture cleanup failed", ([primary] if primary else []) + errors
        )


@pytest.fixture
def account_context(captured, tmp_path):
    bootstrap, ports = captured
    value = _Context(
        ports=ports,
        tmp_path=tmp_path,
        latest=None,
        baseline=None,
        engines=[],
        listeners=[],
        sql=[],
        entries=Counter(),
        final_connection=None,
        final_thread=None,
    )
    primary = None
    try:
        _track_engine(value, ports["account_engine"], "account")
        _track_engine(value, ports["venue_engine"], "venue")
        # Exactly one original initialization per independently fresh captured root.
        value.genesis = initialize_synthetic_session(bootstrap, **ports)
        value.r1 = value.genesis.account.coordinator.acquire("synthetic-account-context")
        value.latest = value.r1
        value.head_before = _rows(ports["account_engine"], (phase2_account_lease_heads,))[
            phase2_account_lease_heads.name
        ][0]
        assert value.genesis.lease.fencing_generation == 1
        assert value.r1.fencing_generation == value.genesis.lease.fencing_generation + 1
        assert value.r1.revision_number == 1 and value.r1.previous_lease_sha256 is None
        assert value.r1.expires_at - value.r1.heartbeat_at == timedelta(seconds=60)
        policy = value.genesis.account.coordinator._authority.policy
        assert policy.lease_ttl == timedelta(seconds=60)
        assert policy.maximum_in_flight_duration == timedelta(seconds=5)
        assert policy.takeover_safety_interval == timedelta(seconds=10)
        ports["clock"].advance_to(value.r1.acquired_at + timedelta(seconds=1))
        value.current = reconstruct_synthetic_session_owners(value.genesis, lease=value.r1)
        account, daily = value.current.account, value.current.daily
        assert type(account) is SqlContinuousAccount
        assert type(account.composer) is SqlContinuousCommitComposer
        assert account is not value.genesis.account and daily is not value.genesis.daily
        assert account.engine is daily.engine is ports["account_engine"]
        assert account.journal._engine is ports["account_engine"]
        assert account.journal._codec is codec
        assert account.coordinator is daily.coordinator is value.genesis.account.coordinator
        assert account.artifacts is account.composer.artifacts is ports["account_artifacts"]
        assert account.codec is account.composer.codec is daily.codec is codec
        assert account.composer.engine is ports["account_engine"]
        assert account.composer.coordinator is account.coordinator
        assert account.composer.daily is daily
        assert account.composer.producer_history is daily.producers is value.current.runtime
        assert account.composer.venue_sources is value.current.venue_sources
        assert value.current.venue_sources is value.genesis.owners.publisher.sources
        assert value.current.runtime.accounts is account and value.current.runtime.daily is daily
        assert account.composer.fence == value.current.runtime.current_fence() == value.r1.fence
        value.c = account.restore(value.genesis.scope)
        assert value.c is not None
        account.require_resolved(value.c)
        value.raw = daily.read_snapshot(
            account_id=value.genesis.scope.account_id, fence=value.r1.fence
        )
        value.b = daily.resolve_snapshot(value.raw)
        daily.require_resolved_snapshot(value.b)
        assert value.b.assignment is None and not value.b.assignment_rows
        assert not value.b.admissions and not value.b.obligations.bindings
        assert (
            not value.b.attempts and not value.b.attempt_envelopes and not value.b.observed_groups
        )
        assert len(value.b.control.blocking_events) == 1
        assert all(
            not rows for rows in _rows(ports["account_engine"], DAILY_RUNTIME_TABLES).values()
        )
        checkpoint = value.c.checkpoint
        assert checkpoint.inputs.spec.live_authorized is False
        assert checkpoint.inputs.spec.initial_cash == Decimal("10000")
        assert len(checkpoint.state.cash_flows) == 1
        assert checkpoint.state.cash_flows[0].amount == Decimal("10000")
        assert not checkpoint.state.submissions and not checkpoint.state.broker_events
        assert not checkpoint.state.commitments and not checkpoint.runtime_decisions
        value.scope = value.c.receipt.commit.scope
        assert (
            value.scope.account_id,
            value.scope.account_binding_sha256,
            value.scope.stream_id,
            value.scope.environment,
        ) == (
            checkpoint.inputs.spec.account_id,
            checkpoint.inputs.spec.account_binding_sha256,
            checkpoint.inputs.spec.deployment_id,
            checkpoint.inputs.spec.environment,
        )
        assert value.c.receipt.commit.transition.account_id == value.scope.account_id
        assert (
            value.c.receipt.commit.transition.account_binding_sha256
            == value.scope.account_binding_sha256
        )
        value.raw_receipt_sha256 = value.raw.receipt.semantic_sha256
        assert (
            value.raw.receipt.fence,
            value.raw.receipt.lease_sha256,
            value.raw.receipt.policy_sha256,
            value.raw.receipt.valid_until,
        ) == (
            value.r1.fence,
            value.r1.semantic_sha256,
            value.r1.policy_sha256,
            value.r1.expires_at,
        )
        assert value.r1.heartbeat_at <= value.raw.receipt.validated_at < value.r1.expires_at
        value.reference = ports["account_artifacts"].put(_PAYLOAD)
        assert value.reference.byte_count == len(_PAYLOAD) <= MAX_OBJECT_BYTES == 64 * 1024 * 1024
        value.operation = ports["clock"].now()
        security = LocalOperatorSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id=_OWNER,
            configured_secret="synthetic-test-only-account-context-configuration",
        )
        response = Response()
        capability = security.bootstrap_capability(
            response,
            persistence_ready=True,
            issued_at=value.operation,
            session_cookie=None,
        )
        cookies = SimpleCookie()
        cookies.load(response.headers["set-cookie"])
        value.cookie, value.csrf = cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token
        value.issuer = LocalOperationalControlOperatorStatementAuthenticator(
            security, scope_id=value.scope.account_id, actor_authority_sha256=_AUTHORITY
        )
        value.reader = OperatorStatementEvidenceReader(
            ports["account_artifacts"], max_bytes=len(_PAYLOAD)
        )
        value.clock_port = ports["clock"].now
        value.preparer = OperatorStatementRecordPreparer(
            value.issuer, value.reader, clock=value.clock_port
        )
        value.journal = SqlDurableJournal(
            ports["account_engine"],
            codec=codec,
            record_types={
                OPERATOR_STATEMENT_RECORD_SCHEMA: OperationalControlOperatorStatementRecord
            },
        )
        assert value.preparer.clock is value.clock_port
        value.graph = _graph(value)
        value.baseline = _inventory(value)
        with _observe(value):
            _assert_unchanged(value)
            yield value
    except BaseException as error:
        primary = error
        raise
    finally:
        _finish(value, primary)


def _prepare(value, scope=None):
    """Use genuine I/F/J APIs outside SQL; install or publish no statement."""
    scope = value.scope if scope is None else scope
    control = value.b.control
    blocker = control.blocking_events[0]
    statement = OperationalControlOperatorStatement(
        scope_id=value.raw.account_id,
        control_transition_id=control.transition_id,
        control_transition_sha256=control.semantic_sha256,
        control_sequence_number=control.sequence_number,
        control_state=control.effective_state,
        control_state_epoch_id=control.state_epoch_id,
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
        idempotency_key="account-context-statement-0001",
    )
    authenticated = value.issuer.authenticate(
        statement, session_cookie=value.cookie, csrf_token=value.csrf, now=value.operation
    )
    value.ports["clock"].advance_to(value.operation + timedelta(milliseconds=100))
    prepared = value.preparer.prepare(
        authenticated, value.reference, session_cookie=value.cookie, csrf_token=value.csrf
    )
    assert type(prepared) is PreparedOperationalControlOperatorStatementRecord
    record = prepared.record
    assert type(record) is OperationalControlOperatorStatementRecord
    assert type(record.statement) is OperationalControlOperatorStatement
    assert type(record.evidence) is ObjectRef
    assert prepared.authenticated is authenticated
    assert record.statement is not authenticated.statement
    assert record.evidence is not value.reference
    assert _projection(record.statement) == _projection(statement)
    assert record.evidence == value.reference
    assert (
        record.session_expires_at
        == authenticated.session_expires_at
        == value.operation + timedelta(hours=8)
    )
    assert (
        record.statement.actor.authenticated_at
        == record.statement.authentication_checked_at
        == record.statement.attested_at
        == value.operation
    )
    assert value.operation <= prepared.before_read_at <= prepared.checked_at
    actual = record.statement
    assert (
        actual.scope_id,
        actual.control_transition_id,
        actual.control_transition_sha256,
        actual.control_sequence_number,
        actual.control_state,
        actual.control_state_epoch_id,
    ) == (
        value.scope.account_id,
        control.transition_id,
        control.semantic_sha256,
        control.sequence_number,
        control.effective_state,
        control.state_epoch_id,
    )
    assert (
        actual.blocking_event.event_id,
        actual.blocking_event.semantic_sha256,
        _projection(actual.blocking_event),
    ) in tuple(
        (item.event_id, item.semantic_sha256, _projection(item)) for item in control.blocking_events
    )
    key = operator_statement_journal_key(scope)
    head = value.journal.read_head(key)
    assert head == empty_head(key)
    offset = len(value.sql)
    returned_key, request = operator_statement_journal_append(scope, record, expected_head=head)
    journal_prepared = value.journal.prepare_append(returned_key, request)
    assert value.sql[offset:] == []
    assert returned_key == key
    assert key.account_scope == record.statement.scope_id == value.scope.account_id
    assert key.source_scope_sha256 == scope.semantic_sha256
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
    assert (
        stored.record_id == request.command_id
        and stored.schema_id == OPERATOR_STATEMENT_RECORD_SCHEMA
    )
    assert (
        type(stored.payload) is bytes and 0 < len(stored.payload) <= MAX_RECORD_BYTES == 256 * 1024
    )
    assert sum(len(item.payload) for item in request.records) <= MAX_APPEND_BYTES == 1024 * 1024
    assert stored.payload == codec.encode_record(
        copy_operational_control_operator_statement_record(record)
    )
    assert _projection(
        codec.decode_record(stored.payload, OperationalControlOperatorStatementRecord)
    ) == _projection(record)
    assert journal_prepared.key is returned_key and journal_prepared.request is request
    assert journal_prepared.receipt.command_id == request.command_id
    assert journal_prepared.receipt.command_sha256 == request.command_sha256
    assert journal_prepared.receipt.previous_head == head
    assert journal_prepared.receipt.record_ids == (stored.record_id,)
    assert journal_prepared.receipt.record_hashes == (hashlib.sha256(stored.payload).hexdigest(),)
    assert len(journal_prepared.entries) == 1
    assert journal_prepared.entries[0].record is stored
    assert journal_prepared.entries[0].head == journal_prepared.receipt.committed_head
    assert journal_prepared.receipt.committed_head.sequence == 1 < MAX_SEQUENCE
    assert journal_prepared.receipt.committed_head != value.journal.read_head(key) == head
    value.ports["clock"].advance_to(value.operation + timedelta(milliseconds=200))
    value.current.account.require_resolved(value.c)
    value.current.daily.require_resolved_snapshot(value.b)
    assert (
        value.preparer.require_prepared(
            prepared, session_cookie=value.cookie, csrf_token=value.csrf
        )
        is None
    )
    assert (
        prepared.checked_at
        <= value.ports["clock"].now()
        < min(record.session_expires_at, value.r1.expires_at)
    )
    assert tuple(
        value.entries[label] for label in ("authenticate", "evidence", "read", "prepare")
    ) == (4, 1, 1, 1)
    return prepared, journal_prepared


def test_genuine_c1_i_j_b_and_current_c_have_exact_r1_agreement(account_context):
    value = account_context
    prepared, journal_prepared = _prepare(value)
    actual_scope = value.c.receipt.commit.scope
    assert (
        value.scope.account_id,
        value.scope.account_binding_sha256,
        value.scope.stream_id,
        value.scope.environment,
    ) == (
        actual_scope.account_id,
        actual_scope.account_binding_sha256,
        actual_scope.stream_id,
        actual_scope.environment,
    )
    with _account_interval(value), value.current.account.write_transaction() as connection:
        value.final_connection = connection
        assert connection.engine is value.ports["account_engine"] and connection.in_transaction()
        assert connection.connection.driver_connection.in_transaction is True
        b_receipt = value.current.daily.recheck_snapshot_in_transaction(
            connection, value.b, fence=value.r1.fence
        )
        assert (
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
            is None
        )
        final_receipt = value.current.account.coordinator.revalidate_for_commit_in_transaction(
            connection, value.r1.fence
        )
    assert (
        (b_receipt.fence, b_receipt.lease_sha256, b_receipt.policy_sha256, b_receipt.valid_until)
        == (
            final_receipt.fence,
            final_receipt.lease_sha256,
            final_receipt.policy_sha256,
            final_receipt.valid_until,
        )
        == (
            value.raw.receipt.fence,
            value.raw.receipt.lease_sha256,
            value.raw.receipt.policy_sha256,
            value.raw.receipt.valid_until,
        )
        == (value.r1.fence, value.r1.semantic_sha256, value.r1.policy_sha256, value.r1.expires_at)
    )
    assert (
        value.r1.heartbeat_at
        <= value.raw.receipt.validated_at
        <= b_receipt.validated_at
        <= final_receipt.validated_at
        < value.r1.expires_at
    )
    assert prepared.checked_at <= final_receipt.validated_at < prepared.record.session_expires_at
    assert (
        value.c.receipt.fence_reference.lease_sha256
        == value.genesis.lease.semantic_sha256
        != value.r1.semantic_sha256
    )
    assert (
        value.raw.receipt is not b_receipt
        and value.raw.receipt.semantic_sha256 != b_receipt.semantic_sha256
    )
    assert journal_prepared.receipt.committed_head != value.journal.read_head(journal_prepared.key)
    _assert_unchanged(value)


@pytest.mark.parametrize("field", ["account_binding_sha256", "stream_id"])
def test_valid_declared_j_mismatch_is_explicitly_unequal_to_actual_c(account_context, field):
    value = account_context
    declared = replace(
        value.scope,
        **{field: "d" * 64 if field == "account_binding_sha256" else "different-deployment"},
    )
    prepared, journal_prepared = _prepare(value, declared)
    names = ("account_id", "account_binding_sha256", "stream_id", "environment")
    actual = value.c.receipt.commit.scope
    assert tuple(getattr(declared, name) == getattr(actual, name) for name in names) == tuple(
        name != field for name in names
    )
    assert tuple(getattr(declared, name) for name in names) != tuple(
        getattr(actual, name) for name in names
    )
    with _account_interval(value), value.current.account.write_transaction() as connection:
        value.final_connection = connection
        assert connection.engine is value.ports["account_engine"]
        assert connection.connection.driver_connection.in_transaction is True
        b_receipt = value.current.daily.recheck_snapshot_in_transaction(
            connection, value.b, fence=value.r1.fence
        )
        assert (
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
            is None
        )
        final_receipt = value.current.account.coordinator.revalidate_for_commit_in_transaction(
            connection, value.r1.fence
        )
    assert (
        (b_receipt.fence, b_receipt.lease_sha256, b_receipt.policy_sha256, b_receipt.valid_until)
        == (
            final_receipt.fence,
            final_receipt.lease_sha256,
            final_receipt.policy_sha256,
            final_receipt.valid_until,
        )
        == (
            value.raw.receipt.fence,
            value.raw.receipt.lease_sha256,
            value.raw.receipt.policy_sha256,
            value.raw.receipt.valid_until,
        )
        == (value.r1.fence, value.r1.semantic_sha256, value.r1.policy_sha256, value.r1.expires_at)
    )
    assert (
        prepared.checked_at
        <= final_receipt.validated_at
        < min(value.r1.expires_at, prepared.record.session_expires_at)
    )
    assert journal_prepared.receipt.committed_head != value.journal.read_head(journal_prepared.key)
    _assert_unchanged(value)


@pytest.mark.parametrize("kind", ["copy", "startup-owner"])
def test_original_c_ownership_guards_reject_copy_and_foreign_owner(account_context, kind):
    value = account_context
    _prepare(value)
    account = value.current.account if kind == "copy" else value.genesis.account
    resolved = replace(value.c) if kind == "copy" else value.c
    if kind == "copy":
        assert resolved is not value.c and resolved == value.c
    offset = len(value.sql)
    with pytest.raises(ContinuousAccountConflict, match=r"^OWNED_CONTINUOUS_VALUE_REQUIRED$"):
        account.require_resolved(resolved)
    assert value.sql[offset:] == []
    value.current.account.require_resolved(value.c)
    _assert_unchanged(value)


@pytest.mark.parametrize("kind", ["foreign-engine", "logical-only"])
def test_original_c_native_transaction_guard_rejects_before_data_queries(account_context, kind):
    value = account_context
    _prepare(value)
    engine = value.ports["account_engine"]
    if kind == "foreign-engine":
        engine = create_database_engine(
            f"sqlite+pysqlite:///{value.tmp_path / 'foreign-empty.sqlite'}"
        )
        _track_engine(value, engine, "foreign")
        with (
            pytest.raises(
                ContinuousAccountConflict, match=r"^SAME_ENGINE_ACTIVE_TRANSACTION_REQUIRED$"
            ),
            _account_interval(value),
            _write_transaction(engine) as connection,
        ):
            value.final_connection = connection
            assert connection.engine is not value.current.account.engine
            assert connection.connection.driver_connection.in_transaction is True
            offset = len(value.sql)
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
    else:
        with (
            pytest.raises(
                ContinuousAccountConflict, match=r"^SQLITE_PHYSICAL_TRANSACTION_REQUIRED$"
            ),
            _account_interval(value),
            engine.connect() as connection,
            connection.begin(),
        ):
            value.final_connection = connection
            assert connection.engine is value.current.account.engine and connection.in_transaction()
            assert connection.connection.driver_connection.in_transaction is False
            offset = len(value.sql)
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
    # The exact original C exception has escaped/rolled back its context already.
    assert value.sql[offset:] == []
    _assert_unchanged(value)


def test_original_same_fence_r2_passes_rechecks_but_is_not_retained_r1(account_context):
    value = account_context
    prepared, journal_prepared = _prepare(value)
    value.ports["clock"].advance_to(value.operation + timedelta(seconds=1))
    value.latest = value.current.account.coordinator.renew(value.r1.fence)
    r2 = value.latest
    assert r2.fence == value.r1.fence and r2.fencing_generation == value.r1.fencing_generation
    assert r2.revision_number == 2 and r2.previous_lease_sha256 == value.r1.semantic_sha256
    assert r2.policy_sha256 == value.r1.policy_sha256
    assert r2.expires_at - r2.heartbeat_at == timedelta(seconds=60)
    assert r2.heartbeat_at < value.r1.expires_at < r2.expires_at
    # Authenticate current I use again after the sole adverse renewal, outside SQL.
    value.current.account.require_resolved(value.c)
    value.current.daily.require_resolved_snapshot(value.b)
    assert (
        value.preparer.require_prepared(
            prepared, session_cookie=value.cookie, csrf_token=value.csrf
        )
        is None
    )
    with _account_interval(value), value.current.account.write_transaction() as connection:
        value.final_connection = connection
        assert connection.engine is value.ports["account_engine"]
        assert connection.connection.driver_connection.in_transaction is True
        b_receipt = value.current.daily.recheck_snapshot_in_transaction(
            connection, value.b, fence=value.r1.fence
        )
        assert (
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
            is None
        )
        final_receipt = value.current.account.coordinator.revalidate_for_commit_in_transaction(
            connection, value.r1.fence
        )
    assert (
        (b_receipt.fence, b_receipt.lease_sha256, b_receipt.policy_sha256, b_receipt.valid_until)
        == (
            final_receipt.fence,
            final_receipt.lease_sha256,
            final_receipt.policy_sha256,
            final_receipt.valid_until,
        )
        == (r2.fence, r2.semantic_sha256, r2.policy_sha256, r2.expires_at)
    )
    assert (
        final_receipt.fence,
        final_receipt.lease_sha256,
        final_receipt.policy_sha256,
        final_receipt.valid_until,
    ) != (value.r1.fence, value.r1.semantic_sha256, value.r1.policy_sha256, value.r1.expires_at)
    assert value.raw.receipt.lease_sha256 == value.r1.semantic_sha256
    assert (
        value.r1.heartbeat_at
        <= value.raw.receipt.validated_at
        <= prepared.checked_at
        < b_receipt.validated_at
        <= final_receipt.validated_at
        < value.r1.expires_at
    )
    assert final_receipt.validated_at < prepared.record.session_expires_at
    assert value.c.receipt.fence_reference.lease_sha256 == value.genesis.lease.semantic_sha256
    assert journal_prepared.receipt.committed_head != value.journal.read_head(journal_prepared.key)
    _assert_unchanged(value)
