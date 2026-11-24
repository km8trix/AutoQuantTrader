"""Twelve bounded fresh synthetic statement-writer scenarios; no live authority."""

import sys
from collections import Counter
from dataclasses import replace
from datetime import timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import Response
from sqlalchemy import Connection

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.operational_control_operator_authentication import (
    LocalOperationalControlOperatorStatementAuthenticator,
)
from apps.api.operational_control_operator_preparation import OperatorStatementRecordPreparer
from apps.api.operational_control_operator_retention import OperatorStatementRetentionService
from apps.trader.operational_control_operator_evidence import OperatorStatementEvidenceReader
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_synthetic_session_owners,
)
from packages.application import personal_codec as codec
from packages.application.operational_control_operator_journal import operator_statement_journal_key
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlIncidentDisposition,
)
from packages.domain.operational_control_operator_record import (
    OPERATOR_STATEMENT_RECORD_SCHEMA,
    OperationalControlOperatorStatementRecord,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured
from tests.integration.test_operational_control_operator_account_context import (
    _inventory,
    _rows,
    _track_engine,
)


class Fixture(SimpleNamespace):
    def __repr__(self):
        return "<synthetic statement fixture>"


class Clock:
    def __init__(self, original):
        self.original = original
        self.samples = []
        self.script = []
        self.trace = []
        self.final_sample = False

    def now(self):
        value = self.script.pop(0) if self.script else self.original.now()
        self.samples.append(value)
        if self.final_sample:
            self.trace.append("t2")
            self.final_sample = False
        return value

    def advance_to(self, value):
        self.original.advance_to(value)


def protected(value):
    inventory = _inventory(value)
    rows = {
        name: tuple(row for row in data if row.get("key_sha256") != value.key.semantic_sha256)
        for name, data in inventory[1].items()
    }
    return inventory[0], rows, *inventory[2:]


@pytest.fixture
def writer(captured, request):
    bootstrap, ports = captured
    ports["clock"] = Clock(ports["clock"])
    value = Fixture(ports=ports, engines=[], listeners=[], sql=[], entries=Counter(), latest=None)
    primary = None
    monitor = sys.monitoring
    tool = next((n for n in (4, 3, 2, 1, 0) if monitor.get_tool(n) is None), None)
    assert tool is not None
    enabled = []
    registered = False
    trace = ports["clock"].trace
    codes = {
        SqlAccountCoordinator.finish_commit_admission.__code__: "finalizer",
        Connection.commit.__code__: "commit",
        codec.encode_record.__code__: "codec",
        codec.decode_record.__code__: "codec",
        OperatorStatementRecordPreparer.require_prepared.__code__: "auth",
    }

    def started(code, offset):
        label = codes[code]
        if label == "finalizer":
            ports["clock"].final_sample = True
        trace.append(label)

    def sql_observed(*args):
        trace.append("sql")

    try:
        _track_engine(value, ports["account_engine"], "account")
        _track_engine(value, ports["venue_engine"], "venue")
        value.genesis = initialize_synthetic_session(bootstrap, **ports)
        value.coordinator = value.genesis.account.coordinator
        value.r1 = value.coordinator.acquire("statement-retention-fixture")
        value.latest = value.r1
        ports["clock"].advance_to(value.r1.acquired_at + timedelta(seconds=1))
        value.current = reconstruct_synthetic_session_owners(value.genesis, lease=value.r1)
        value.c = value.current.account.restore(value.genesis.scope)
        value.raw = value.current.daily.read_snapshot(
            account_id=value.genesis.scope.account_id, fence=value.r1.fence
        )
        value.b = value.current.daily.resolve_snapshot(value.raw)
        value.operation = ports["clock"].now()
        value.reference = ports["account_artifacts"].put(b"synthetic statement evidence\n")
        security = LocalOperatorSecurity(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="statement-test",
            configured_secret="synthetic-fixture-only",
        )
        response = Response()
        # Unchanged 8h policy; this legitimately old synthetic session has 20s left.
        remaining = 120 if request.node.name.startswith("test_w06") else 20
        issued = value.operation - timedelta(hours=8) + timedelta(seconds=remaining)
        capability = security.bootstrap_capability(
            response, persistence_ready=True, issued_at=issued, session_cookie=None
        )
        cookies = SimpleCookie()
        cookies.load(response.headers["set-cookie"])
        value.cookie, value.csrf = cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token
        value.issuer = LocalOperationalControlOperatorStatementAuthenticator(
            security, scope_id=value.genesis.scope.account_id, actor_authority_sha256="a" * 64
        )
        value.preparer = OperatorStatementRecordPreparer(
            value.issuer,
            OperatorStatementEvidenceReader(
                ports["account_artifacts"], max_bytes=value.reference.byte_count
            ),
            clock=ports["clock"].now,
        )
        control = value.b.control
        blocker = control.blocking_events[0]
        statement = OperationalControlOperatorStatement(
            scope_id=value.genesis.scope.account_id,
            control_transition_id=control.transition_id,
            control_transition_sha256=control.semantic_sha256,
            control_sequence_number=control.sequence_number,
            control_state=control.effective_state,
            control_state_epoch_id=control.state_epoch_id,
            blocking_event=blocker,
            actor=OperationalControlActor(
                actor_id="statement-test",
                kind=OperationalControlActorKind.HUMAN,
                authority_sha256="a" * 64,
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
            idempotency_key="statement-retention-test-0001",
        )
        authenticated = value.issuer.authenticate(
            statement, session_cookie=value.cookie, csrf_token=value.csrf, now=value.operation
        )
        value.prepared = value.preparer.prepare(
            authenticated, value.reference, session_cookie=value.cookie, csrf_token=value.csrf
        )
        value.journal = SqlDurableJournal(
            ports["account_engine"],
            codec=codec,
            record_types={
                OPERATOR_STATEMENT_RECORD_SCHEMA: OperationalControlOperatorStatementRecord
            },
        )
        value.key = operator_statement_journal_key(value.genesis.scope)
        value.head = value.journal.read_head(value.key)
        value.service = OperatorStatementRetentionService(
            value.preparer, value.current.account, value.current.daily, value.journal
        )
        value.baseline = protected(value)
        sa.event.listen(ports["account_engine"], "before_cursor_execute", sql_observed)
        value.listeners.append((ports["account_engine"], "before_cursor_execute", sql_observed))
        monitor.use_tool_id(tool, "aqt-writer-order")
        assert monitor.register_callback(tool, monitor.events.PY_START, started) is None
        registered = True
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START)
        yield value
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for code in enabled:
            monitor.set_local_events(tool, code, 0)
            assert monitor.get_local_events(tool, code) == 0
        if registered:
            assert monitor.register_callback(tool, monitor.events.PY_START, None) is started
            monitor.free_tool_id(tool)
            assert monitor.get_tool(tool) is None

        try:
            if hasattr(value, "baseline"):
                assert protected(value) == value.baseline
            if value.latest is not None:
                assert value.coordinator.current() == value.latest
                if ports["clock"].now() < value.latest.expires_at:
                    release = value.coordinator.release(value.latest.fence)
                    assert release.lease_sha256 == value.latest.semantic_sha256
                    assert value.coordinator.current() is None
                else:
                    # W06 exhausted lease: never renew/backdate/adopt for cleanup.
                    assert value.latest is value.r1
                leases = _rows(ports["account_engine"], (phase2_account_leases,))[
                    phase2_account_leases.name
                ]
                assert len(leases) == (2 if value.latest is value.r1 else 3)
            if hasattr(value, "baseline"):
                assert protected(value) == value.baseline
        except BaseException as error:
            errors.append(error)
        for _engine, connections, _label in value.engines:
            try:
                assert all(connection.closed for connection in connections)
            except BaseException as error:
                errors.append(error)
        for engine, event, listener in reversed(value.listeners):
            sa.event.remove(engine, event, listener)
            assert not sa.event.contains(engine, event, listener)
        if errors:
            raise BaseExceptionGroup(
                "statement fixture cleanup", ([primary] if primary else []) + errors
            )


def check_order(trace, outcome):
    if outcome.invocation_commit in ("returned_successfully", "unknown"):
        assert trace.count("commit") == 1 and trace.count("t2") == 1
        sample, commit = trace.index("t2"), trace.index("commit")
        assert commit == sample + 1
    else:
        assert "commit" not in trace


def invoke(value):
    start = len(value.ports["clock"].trace)
    outcome = value.service.retain(
        value.prepared,
        current_account=value.c,
        current_risk=value.b,
        expected_statement_head=value.head,
        session_cookie=value.cookie,
        csrf_token=value.csrf,
    )
    check_order(value.ports["clock"].trace[start:], outcome.write)
    return outcome


def invoke_request(value, request):
    start = len(value.ports["clock"].trace)
    outcome = value.current.account.retain_statement(request)
    check_order(value.ports["clock"].trace[start:], outcome)
    return outcome


def absent(value):
    assert value.journal.read_head(value.key) == value.head
    assert protected(value) == value.baseline


def present(value):
    assert value.journal.read_head(value.key).sequence == 1
    assert protected(value) == value.baseline


def candidate_request(value):
    candidate = value.current.account.prepare_statement_candidate(
        account=value.c,
        risk=value.b,
        daily=value.current.daily,
        journal=value.journal,
        record=value.prepared.record,
        expected_head=value.head,
        prepared_at=value.prepared.checked_at,
    )
    observation = value.preparer.observe_prepared(
        value.prepared, session_cookie=value.cookie, csrf_token=value.csrf
    )
    value.preparer.consume_admission(observation)
    return value.current.account.prepare_statement_write(
        candidate,
        authenticated_at=observation.checked_at,
        expires_at=observation.expires_at,
        clock=value.ports["clock"],
    )


def test_w01_fresh_retention(writer):
    # Additional bounded ownership probes use this same fixture, with zero writes.
    observation = writer.preparer.observe_prepared(
        writer.prepared, session_cookie=writer.cookie, csrf_token=writer.csrf
    )
    with pytest.raises(ValueError):
        writer.preparer.consume_admission(replace(observation))
    foreign = OperatorStatementRecordPreparer(
        writer.issuer, writer.preparer.reader, clock=writer.preparer.clock
    )
    with pytest.raises(ValueError):
        foreign.consume_admission(observation)
    writer.preparer.consume_admission(observation)
    with pytest.raises(ValueError):
        writer.preparer.consume_admission(observation)
    assert (
        writer.preparer.require_prepared(
            writer.prepared, session_cookie=writer.cookie, csrf_token=writer.csrf
        )
        is None
    )
    request = candidate_request(writer)
    copied = invoke_request(writer, replace(request))
    assert str(copied.primary) == "ORIGINAL_STATEMENT_OPERATION_REQUIRED"
    # No execution of the original unused request; the normal service still owns
    # the one actual append below.
    outcome = invoke(writer)
    assert outcome.write.primary is None and outcome.write.cleanup == "verified_complete"
    assert outcome.write.statement_retention == "committed_fresh"
    assert (
        outcome.write.invocation_commit == "returned_successfully"
        and outcome.delivery == "delivered"
    )
    present(writer)


def test_w02_expiry_before_admission(writer):
    writer.ports["clock"].advance_to(writer.prepared.record.session_expires_at)
    with pytest.raises(ValueError):
        invoke(writer)
    absent(writer)


def test_w03_expiry_at_actual_head_lock_boundary(writer, monkeypatch):
    original = type(writer.coordinator)._head
    observed = []

    def after_lock(coordinator, connection, *, lock):
        result = original(coordinator, connection, lock=lock)
        if coordinator is writer.coordinator and lock and not observed:
            observed.append(True)
            writer.ports["clock"].advance_to(writer.prepared.record.session_expires_at)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(type(writer.coordinator), "_head", after_lock)
        outcome = invoke(writer)
    assert observed and outcome.write.primary is not None
    assert outcome.write.invocation_commit == "failed_before_attempt_with_rollback"
    absent(writer)


def test_w04_expiry_after_readbacks(writer, monkeypatch):
    original = type(writer.coordinator).prepare_commit_admission_in_transaction

    def after_reads(coordinator, connection, fence):
        assert coordinator is writer.coordinator
        ticket = original(coordinator, connection, fence)
        writer.ports["clock"].advance_to(writer.prepared.record.session_expires_at)
        return ticket

    with monkeypatch.context() as patch:
        patch.setattr(
            type(writer.coordinator), "prepare_commit_admission_in_transaction", after_reads
        )
        outcome = invoke(writer)
    assert outcome.write.record_origin == "fresh_candidate" and outcome.write.primary is not None
    assert outcome.write.invocation_commit == "failed_before_attempt_with_rollback"
    absent(writer)


def test_w05_final_time_before_postlock_sample(writer, monkeypatch):
    original = type(writer.coordinator).prepare_commit_admission_in_transaction
    seen = []

    def scripted(coordinator, connection, fence):
        assert coordinator is writer.coordinator
        base = writer.ports["clock"].now()
        writer.ports["clock"].script = [base + timedelta(seconds=10), base + timedelta(seconds=12)]
        ticket = original(coordinator, connection, fence)
        seen.extend((ticket.t0, ticket.t1))
        writer.ports["clock"].advance_to(base + timedelta(seconds=12))
        writer.ports["clock"].script = [base + timedelta(seconds=11)]
        return ticket

    with monkeypatch.context() as patch:
        patch.setattr(type(writer.coordinator), "prepare_commit_admission_in_transaction", scripted)
        outcome = invoke(writer)
    assert len(seen) == 2 and seen[1] - seen[0] == timedelta(seconds=2)
    assert outcome.write.primary is not None and "regress" in str(outcome.write.primary)
    absent(writer)


def test_w06_original_lease_expiry(writer):
    # Prepare while valid; exercise persistence original lease denial directly.
    request = candidate_request(writer)
    writer.ports["clock"].advance_to(writer.r1.expires_at)
    outcome = invoke_request(writer, request)
    assert outcome.primary is not None and outcome.record_origin == "not_established"
    assert outcome.invocation_commit == "failed_before_attempt_with_rollback"
    absent(writer)


def test_w07_same_fence_renewal_rejected(writer):
    request = candidate_request(writer)
    writer.ports["clock"].advance_to(writer.operation + timedelta(seconds=1))
    writer.latest = writer.coordinator.renew(writer.r1.fence)
    outcome = invoke_request(writer, request)
    assert str(outcome.primary) == "STATEMENT_EXACT_OPERATION_LEASE_REQUIRED"
    absent(writer)


def test_w08_readback_failure_rolls_back(writer, monkeypatch):
    error = ValueError("synthetic final readback failure")

    def fail(*args, **kwargs):
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(writer.journal, "recheck_prepared_append_in_transaction", fail)
        outcome = invoke(writer)
    assert outcome.write.primary is error and outcome.write.record_origin == "fresh_candidate"
    absent(writer)


def test_w09_historical_retention_is_not_fresh(writer, monkeypatch):
    first = invoke(writer)
    assert first.write.statement_retention == "committed_fresh"
    original = type(writer.coordinator).prepare_commit_admission_in_transaction

    def expires(coordinator, connection, fence):
        assert coordinator is writer.coordinator
        ticket = original(coordinator, connection, fence)
        writer.ports["clock"].advance_to(writer.prepared.record.session_expires_at)
        return ticket

    with monkeypatch.context() as patch:
        patch.setattr(type(writer.coordinator), "prepare_commit_admission_in_transaction", expires)
        second = invoke(writer)
    assert second.write.record_origin == "already_retained"
    assert second.write.statement_retention == "verified_historical"
    assert second.write.invocation_commit == "failed_before_attempt_with_rollback"
    assert second.delivery == "not_attempted"
    present(writer)


def test_w10_commit_acknowledgement_unknown(writer, monkeypatch):
    original = Connection.commit
    error = RuntimeError("synthetic lost commit acknowledgement")
    observed = []

    def lost(connection):
        original(connection)
        if connection.engine is writer.ports["account_engine"] and not observed:
            observed.append(True)
            raise error

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "commit", lost)
        outcome = invoke(writer)
    assert observed and outcome.write.primary is error
    assert (
        outcome.write.invocation_commit == "unknown"
        and outcome.write.statement_retention == "unknown"
    )
    assert outcome.delivery == "not_attempted"
    present(writer)


def test_w11_cleanup_failure_preserves_commit(writer, monkeypatch):
    original = Connection.close
    error = RuntimeError("synthetic close acknowledgement failure")
    observed = []

    def failed_close(connection):
        original(connection)
        # Retain method removes registration before close; identify committed head
        # through its explicitly captured connection, never by reading SQL here.
        if connection is target[0] and not observed:
            observed.append(True)
            raise error

    target = [None]
    original_finish = type(writer.coordinator).finish_commit_admission

    def finish(coordinator, ticket, **kwargs):
        assert coordinator is writer.coordinator
        target[0] = writer.coordinator._commit_admissions[id(ticket)].connection
        return original_finish(coordinator, ticket, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(type(writer.coordinator), "finish_commit_admission", finish)
        patch.setattr(Connection, "close", failed_close)
        outcome = invoke(writer)
    assert observed and outcome.write.primary is None
    assert (
        outcome.write.statement_retention == "committed_fresh" and outcome.write.cleanup == "failed"
    )
    assert error in outcome.write.cleanup_errors and outcome.delivery == "not_attempted"
    present(writer)


def test_w12_delivery_expiry_preserves_commit(writer, monkeypatch):
    original = Connection.commit
    observed = []

    def expire_after_commit(connection):
        original(connection)
        if connection.engine is writer.ports["account_engine"] and not observed:
            observed.append(True)
            writer.ports["clock"].advance_to(writer.prepared.record.session_expires_at)

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "commit", expire_after_commit)
        outcome = invoke(writer)
    assert observed and outcome.write.statement_retention == "committed_fresh"
    assert outcome.write.cleanup == "verified_complete" and outcome.delivery == "rejected_or_failed"
    present(writer)
