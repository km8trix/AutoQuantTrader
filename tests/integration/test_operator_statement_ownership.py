"""Fourteen approved disposable SQLite ownership probes; no product changes."""

import json
import os
import sys
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from threading import Thread
from types import SimpleNamespace

import pytest
from sqlalchemy import Connection, Engine

from packages.domain.account_coordinator import AccountCoordinatorError
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from tests.integration.test_operational_control_operator_account_context import _rows
from tests.integration.test_operator_statement_retention import (
    Clock,
    candidate_request,
    check_order,
    protected,
)
from tests.integration.test_operator_statement_retention import (
    captured as captured,
)
from tests.integration.test_operator_statement_retention import (
    writer as writer,
)


def statement_rows(value):
    return {
        name: tuple(row for row in rows if row["key_sha256"] == value.key.semantic_sha256)
        for name, rows in _rows(value.ports["account_engine"], JOURNAL_TABLES).items()
    }


@contextmanager
def window(value):
    """Observe actual selected native entries, including worker-thread calls."""
    codes = {
        Engine.connect.__code__: "connect",
        Connection.commit.__code__: "commit",
        Connection.rollback.__code__: "rollback",
        SqlContinuousAccount._begin_cooperative_write.__code__: "token",
        SqlDurableJournal.append_classified_in_transaction.__code__: "append",
        SqlDurableJournal.recheck_prepared_append_in_transaction.__code__: "readback",
        SqlAccountCoordinator.prepare_commit_admission_in_transaction.__code__: "ticket",
        SqlAccountCoordinator.finish_commit_admission.__code__: "finish",
        Clock.now.__code__: "clock",
    }
    counts = Counter()
    trace = []
    sql = len(value.sql)
    monitor = sys.monitoring
    tool = next(n for n in (3, 2, 1, 0) if monitor.get_tool(n) is None)

    def entered(code, offset):
        label = codes[code]
        counts[label] += 1
        trace.append(label)

    monitor.use_tool_id(tool, "aqt-ownership-window")
    assert monitor.register_callback(tool, monitor.events.PY_START, entered) is None
    try:
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            monitor.set_local_events(tool, code, monitor.events.PY_START)
        yield counts
    finally:
        for code in codes:
            monitor.set_local_events(tool, code, 0)
            assert monitor.get_local_events(tool, code) == 0
        assert monitor.register_callback(tool, monitor.events.PY_START, None) is entered
        monitor.free_tool_id(tool)
        counts["sql"] = len(value.sql) - sql
        value.ownership_windows.append({"counts": dict(counts), "trace": trace})


def quiet(counts, *, finish=0):
    assert counts == Counter({"finish": finish, "sql": 0})


def resources(value):
    owner = value.current.account
    assert not owner._write_connections and not owner._cooperative_writes
    assert not value.coordinator._commit_admissions
    assert owner._statement_write_lock.acquire(blocking=False)
    owner._statement_write_lock.release()


def denial(value, operation, code):
    with window(value) as counts:
        outcome = operation()
    assert type(outcome.primary) is ValueError and str(outcome.primary) == code
    assert outcome.cleanup == "verified_complete" and not outcome.cleanup_errors
    assert outcome.invocation_commit == "not_attempted"
    quiet(counts)
    resources(value)
    return outcome


def worker_once(operation):
    result = []

    def work():
        try:
            result.append((True, operation()))
        except BaseException as error:
            result.append((False, error))

    thread = Thread(target=work, name="aqt-ownership-denial", daemon=True)
    thread.start()
    thread.join(timeout=2)
    if thread.is_alive():
        # Hard exit skips fixture finally blocks: no cleanup can race this worker.
        # Parent reaps the sole child before reading/removing the owned tree.
        try:
            path = Path(os.environ["TMPDIR"]) / "thread-abort.json"
            path.write_text(json.dumps({"reason": "worker_join_timeout", "seconds": 2}))
        finally:
            os._exit(86)
    assert len(result) == 1
    ok, answer = result[0]
    if not ok:
        raise answer
    return answer


@pytest.fixture
def owned(writer, request):
    writer.ownership_windows = []
    before = statement_rows(writer)
    yield writer
    resources(writer)
    after = statement_rows(writer)
    if request.node.name.startswith("test_o01"):
        assert all(len(rows) == 1 for rows in after.values())
        assert writer.journal.read_head(writer.key).sequence == 1
        entry = after["personal_journal_entries"][0]
        assert entry["payload"] == writer.journal._codec.encode_record(writer.prepared.record)
        decoded = writer.journal._codec.decode_record(
            entry["payload"], type(writer.prepared.record)
        )
        assert decoded.semantic_sha256 == writer.prepared.record.semantic_sha256
    else:
        assert after == before and writer.journal.read_head(writer.key) == writer.head
    assert protected(writer) == writer.baseline
    (Path(os.environ["TMPDIR"]) / (request.node.name + ".json")).write_text(
        json.dumps({"windows": writer.ownership_windows, "inventory_passed": True}, indent=2)
    )


def test_o01_original_request_is_single_use_after_commit(owned):
    request = candidate_request(owned)
    start = len(owned.ports["clock"].trace)
    with window(owned) as counts:
        outcome = owned.current.account.retain_statement(request)
    check_order(owned.ports["clock"].trace[start:], outcome)
    assert outcome.primary is None and outcome.cleanup == "verified_complete"
    assert outcome.statement_retention == "committed_fresh"
    assert outcome.invocation_commit == "returned_successfully"
    assert counts["append"] == counts["ticket"] == counts["finish"] == counts["commit"] == 1
    assert counts["rollback"] == 0
    assert id(request) not in owned.current.account._statement_values
    denial(
        owned,
        lambda: owned.current.account.retain_statement(request),
        "ORIGINAL_STATEMENT_OPERATION_REQUIRED",
    )


def test_o02_wrong_thread_consumes_original_request(owned):
    request = candidate_request(owned)
    denial(
        owned,
        lambda: worker_once(lambda: owned.current.account.retain_statement(request)),
        "STATEMENT_OPERATION_THREAD_CHANGED",
    )
    assert id(request) not in owned.current.account._statement_values
    denial(
        owned,
        lambda: owned.current.account.retain_statement(request),
        "ORIGINAL_STATEMENT_OPERATION_REQUIRED",
    )


def test_o03_changed_request_rejects_before_consumption(owned):
    request = candidate_request(owned)
    original = request.expires_at
    try:
        object.__setattr__(request, "expires_at", original + timedelta(microseconds=1))
        denial(
            owned,
            lambda: owned.current.account.retain_statement(request),
            "STATEMENT_OPERATION_CHANGED",
        )
        assert owned.current.account._statement_values[id(request)] is request
    finally:
        object.__setattr__(request, "expires_at", original)


def test_o04_changed_candidate_rejects_after_request_consumption(owned):
    request = candidate_request(owned)
    original = request.candidate.prepared_at
    try:
        object.__setattr__(request.candidate, "prepared_at", original + timedelta(microseconds=1))
        denial(
            owned,
            lambda: owned.current.account.retain_statement(request),
            "STATEMENT_CANDIDATE_CHANGED",
        )
        assert id(request) not in owned.current.account._statement_values
    finally:
        object.__setattr__(request.candidate, "prepared_at", original)


def test_o05_changed_owner_graph_rejects_before_sql(owned):
    request = candidate_request(owned)
    owner = owned.current.account
    original = owner.artifacts
    try:
        owner.artifacts = object()
        denial(owned, lambda: owner.retain_statement(request), "STATEMENT_OWNER_GRAPH_CHANGED")
        assert id(request) not in owner._statement_values
    finally:
        owner.artifacts = original


def test_o06_late_request_change_rolls_back_staged_append(owned, monkeypatch):
    request = candidate_request(owned)
    original_field = request.expires_at
    original = SqlDurableJournal.recheck_prepared_append_in_transaction
    seen = []

    def after_readback(journal, connection, prepared, *, require_current_head=True):
        assert journal is owned.journal and prepared is request.candidate.append
        result = original(journal, connection, prepared, require_current_head=require_current_head)
        assert not seen
        seen.append((connection, connection.get_transaction()))
        object.__setattr__(request, "expires_at", original_field + timedelta(microseconds=1))
        return result

    try:
        # Window pins the original code before the class hook is installed.
        with window(owned) as counts, monkeypatch.context() as patch:
            patch.setattr(
                SqlDurableJournal, "recheck_prepared_append_in_transaction", after_readback
            )
            outcome = owned.current.account.retain_statement(request)
        assert str(outcome.primary) == "STATEMENT_OPERATION_CHANGED"
        assert outcome.record_origin == "fresh_candidate"
        assert outcome.invocation_commit == "failed_before_attempt_with_rollback"
        assert outcome.cleanup == "verified_complete" and not outcome.cleanup_errors
        assert counts["append"] == counts["readback"] == counts["ticket"] == counts["rollback"] == 1
        assert counts["finish"] == counts["commit"] == 0
        assert len(seen) == 1 and seen[0][0].closed and not seen[0][1].is_active
        assert id(request) not in owned.current.account._statement_values
        resources(owned)
    finally:
        object.__setattr__(request, "expires_at", original_field)


@contextmanager
def direct(value):
    connection = value.ports["account_engine"].connect()
    ticket = None
    roots = []
    try:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        roots.append(connection.get_transaction())
        assert roots[0].is_active and connection.connection.driver_connection.in_transaction
        ticket = value.coordinator.prepare_commit_admission_in_transaction(
            connection, value.r1.fence
        )
        state = value.coordinator._commit_admissions[id(ticket)]
        assert (
            state.ticket is ticket
            and state.connection is connection
            and state.transaction is roots[0]
        )
        yield SimpleNamespace(
            ticket=ticket,
            state=state,
            connection=connection,
            roots=roots,
            bounds=(ticket.t0, ticket.t1),
            deadlines=(ticket.receipt.valid_until,),
        )
    finally:
        if ticket is not None:
            value.coordinator.invalidate_commit_admission(ticket)
            assert id(ticket) not in value.coordinator._commit_admissions
        try:
            active = connection.get_transaction()
            if active is not None:
                assert any(active is root for root in roots)
                connection.rollback()
            assert all(not root.is_active for root in roots)
            assert not connection.in_transaction()
            assert not connection.connection.driver_connection.in_transaction
        finally:
            connection.close()
            assert connection.closed


def finish(value, scope, *, coordinator=None, ticket=None):
    return (coordinator or value.coordinator).finish_commit_admission(
        scope.ticket if ticket is None else ticket,
        lower_bounds=scope.bounds,
        deadlines=scope.deadlines,
    )


def reject_ticket(value, scope, **kwargs):
    with (
        window(value) as counts,
        pytest.raises(
            AccountCoordinatorError, match=r"^original commit admission ticket required$"
        ),
    ):
        finish(value, scope, **kwargs)
    quiet(counts, finish=1)


def test_o07_copied_foreign_and_reused_ticket_ownership(owned):
    with direct(owned) as scope:
        reject_ticket(owned, scope, ticket=replace(scope.ticket))
        assert owned.coordinator._commit_admissions[id(scope.ticket)] is scope.state
        foreign = SqlAccountCoordinator(
            account_id=owned.coordinator.account_id, authority=owned.coordinator._authority
        )
        reject_ticket(owned, scope, coordinator=foreign)
        assert not foreign._commit_admissions
        assert owned.coordinator._commit_admissions[id(scope.ticket)] is scope.state
        with window(owned) as counts:
            final = finish(owned, scope)
        assert counts == Counter({"finish": 1, "clock": 1, "sql": 0})
        assert scope.ticket.t1 <= final < scope.ticket.receipt.valid_until
        assert id(scope.ticket) not in owned.coordinator._commit_admissions
        reject_ticket(owned, scope)


def test_o08_changed_ticket_field_consumes_ticket(owned):
    with direct(owned) as scope:
        original = scope.ticket.t1
        try:
            object.__setattr__(scope.ticket, "t1", original + timedelta(microseconds=1))
            reject_ticket(owned, scope)
            assert id(scope.ticket) not in owned.coordinator._commit_admissions
        finally:
            object.__setattr__(scope.ticket, "t1", original)


def test_o09_changed_nested_receipt_consumes_ticket(owned):
    with direct(owned) as scope:
        fence = scope.ticket.receipt.fence
        original = fence.owner_id
        try:
            object.__setattr__(fence, "owner_id", "different-synthetic-owner")
            reject_ticket(owned, scope)
            assert id(scope.ticket) not in owned.coordinator._commit_admissions
        finally:
            object.__setattr__(fence, "owner_id", original)


def test_o10_changed_clock_binding_consumes_ticket(owned):
    with direct(owned) as scope:
        authority = owned.coordinator._authority
        original = authority.clock
        try:
            authority._clock = object()
            reject_ticket(owned, scope)
            assert id(scope.ticket) not in owned.coordinator._commit_admissions
        finally:
            authority._clock = original


def test_o11_invalidated_ticket_cannot_finish(owned):
    with direct(owned) as scope:
        assert owned.coordinator.invalidate_commit_admission(scope.ticket) is None
        assert owned.coordinator.invalidate_commit_admission(scope.ticket) is None
        assert id(scope.ticket) not in owned.coordinator._commit_admissions
        reject_ticket(owned, scope)


def test_o12_replaced_root_transaction_rejects_ticket(owned):
    with direct(owned) as scope:
        scope.connection.rollback()
        assert not scope.roots[0].is_active
        scope.connection.exec_driver_sql("BEGIN IMMEDIATE")
        scope.roots.append(scope.connection.get_transaction())
        assert scope.roots[1] is not scope.roots[0] and scope.roots[1].is_active
        reject_ticket(owned, scope)
        assert id(scope.ticket) not in owned.coordinator._commit_admissions


def test_o13_wrong_thread_consumes_original_ticket(owned):
    with direct(owned) as scope:
        with (
            window(owned) as counts,
            pytest.raises(
                AccountCoordinatorError, match=r"^original commit admission ticket required$"
            ),
        ):
            worker_once(lambda: finish(owned, scope))
        quiet(counts, finish=1)
        assert id(scope.ticket) not in owned.coordinator._commit_admissions
        reject_ticket(owned, scope)


def test_o14_busy_guard_preserves_unstarted_request(owned):
    request = candidate_request(owned)
    owner = owned.current.account
    assert owner._statement_write_lock.acquire(blocking=False)
    try:
        with (
            window(owned) as counts,
            pytest.raises(ValueError, match=r"^STATEMENT_OPERATION_BUSY$"),
        ):
            owner.retain_statement(request)
        quiet(counts)
        assert owner._statement_values[id(request)] is request
    finally:
        owner._statement_write_lock.release()
