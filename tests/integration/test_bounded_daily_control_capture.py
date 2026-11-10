"""Existing B control capture/replay/recheck on an empty HALTED component schema.

These cases prove control transport, ownership and current-footprint behavior.
The clock is an explicit fixture model; no full readiness/financial or migration
qualification follows. Original B, control and coordinator methods are unchanged.
"""

import sys
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import AccountFenceReceipt, AccountLeasePolicy
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.persistence import daily_runtime_risk as daily
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    _write_transaction,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import create_database_engine
from packages.persistence.immutable import as_aware_utc
from packages.persistence.operational_control import (
    SqlOperationalControlRepository,
    resolve_operational_control_rows,
)
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration.test_sql_account_coordinator import MutableClock

_ACCOUNT = "bounded-control-component"
_AT = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)
_OWNER_ERROR = r"^exact original store-produced object required$"


class _UnusedProducer:
    """Required explicit constructor ports, never a passing source resolver."""

    def __init__(self):
        self.calls = []

    def _forbidden(self, name):
        self.calls.append(name)
        raise AssertionError("plain control capture invoked an unused producer")

    def capture_in_transaction(self, *args, **kwargs):
        self._forbidden("capture")

    def resolve(self, *args, **kwargs):
        self._forbidden("resolve")

    def recheck_in_transaction(self, *args, **kwargs):
        self._forbidden("recheck")


def _rows(case, tables):
    with case.engine.connect() as connection:
        return {
            table.name: tuple(
                dict(row)
                for row in connection.execute(
                    sa.select(table).order_by(*table.primary_key.columns)
                ).mappings()
            )
            for table in tables
        }


def _command(case, kind, key):
    if kind not in (
        OperationalControlCommandKind.INITIALIZE_HALTED,
        OperationalControlCommandKind.HALT,
    ):
        raise AssertionError("component fixture accepts only initial HALTED and HALT")
    initial = kind is OperationalControlCommandKind.INITIALIZE_HALTED
    actor = OperationalControlActor(
        actor_id="component-bootstrap" if initial else "component-operator",
        kind=OperationalControlActorKind.SYSTEM if initial else OperationalControlActorKind.HUMAN,
        authority_sha256="a" * 64,
        authenticated_at=None if initial else case.clock.instant,
    )
    return OperationalControlCommand(
        scope_id=_ACCOUNT,
        idempotency_key=key,
        kind=kind,
        target_state=OperationalControlState.HALTED,
        actor=actor,
        reason_code="component-control-observation",
        reason_evidence_sha256="b" * 64,
        requested_at=case.clock.instant,
    )


def _store(case):
    return daily.SqlDailyRuntimeRisk(
        case.engine,
        coordinator=case.coordinator,
        codec=codec,
        producers=case.producer,
        accounting=case.accounting,
    )


@contextmanager
def _observe(case):
    """Original code entries and Engine events; no passing method replacement."""
    monitor, tool = sys.monitoring, 3
    replay = resolve_operational_control_rows.__code__
    accounting = (PersonalAccounting.advance.__code__, PersonalAccounting.project.__code__)
    codes = (*accounting, replay)
    enabled, registered = [], False
    owned, primary = False, None

    def connect(connection):
        case.connections.append(connection)

    def statement(connection, cursor, text, parameters, context, many):
        # Retain no parameter values, frames, credentials or exception payloads.
        case.sql.append((connection, text, threading.current_thread()))

    def start(code, offset):
        if any(code is original for original in accounting):
            case.accounting_calls.append(code.co_name)
            raise AssertionError("plain control capture invoked financial accounting")
        if code is replay:
            thread = threading.current_thread()
            case.replays.append(thread)
            if case.replay_barrier is not None and thread is case.reader_thread:
                entered, release = case.replay_barrier
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test did not release detached control replay")

    try:
        sa.event.listen(case.engine, "engine_connect", connect)
        case.listeners.append(("engine_connect", connect))
        sa.event.listen(case.engine, "before_cursor_execute", statement)
        case.listeners.append(("before_cursor_execute", statement))
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-bounded-control-component")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for name, callback in reversed(case.listeners):
            try:
                sa.event.remove(case.engine, name, callback)
            except BaseException as error:
                errors.append(error)
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
                assert monitor.get_tool(tool) == "aqt-bounded-control-component"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup(
                "component observation cleanup failed", ([primary] if primary else []) + errors
            )


def _empty_financial_rows(case):
    values = _rows(case, DAILY_RUNTIME_TABLES)
    assert all(rows == () for rows in values.values())
    return values


def _cleanup(case, primary):
    errors = []
    for release in case.barriers:
        try:
            release.set()
        except BaseException as error:
            errors.append(error)
    for thread in case.threads:
        try:
            if thread.ident is not None:
                thread.join(10)
        except BaseException as error:
            errors.append(error)
    active = [thread for thread in case.threads if thread.is_alive()]
    if active:
        errors.append(AssertionError("component worker remains active; resources retained"))
    else:
        errors.extend(case.worker_errors)
        if case.r1 is not None:
            current = None
            try:
                current = case.coordinator.current()
                assert current == case.expected_lease
                assert current.fence == case.r1.fence
            except BaseException as error:
                errors.append(error)
            try:
                # Use only the original fence, even if an observation failed.
                # A foreign generation cannot be adopted for rescue cleanup.
                release = case.coordinator.release(case.r1.fence)
                assert current is not None
                assert release.lease_sha256 == current.semantic_sha256
                assert release.policy_sha256 == case.policy.semantic_sha256
                assert current.heartbeat_at <= release.released_at < current.expires_at
                assert case.coordinator.current() is None
                leases = _rows(case, (phase2_account_leases,))[phase2_account_leases.name]
                actual = tuple(
                    sorted(
                        (account_lease_from_row(row) for row in leases),
                        key=lambda lease: lease.revision_number,
                    )
                )
                assert actual == tuple(case.expected_leases)
                releases = _rows(case, (phase2_account_lease_releases,))[
                    phase2_account_lease_releases.name
                ]
                assert len(releases) == 1 and account_lease_release_from_row(releases[0]) == release
                heads = _rows(case, (phase2_account_lease_heads,))[phase2_account_lease_heads.name]
                assert len(heads) == 1
                assert heads[0]["current_fencing_generation"] is None
                assert heads[0]["current_lease_sha256"] is None
                assert heads[0]["last_fencing_generation"] == current.fencing_generation
                assert as_aware_utc(heads[0]["updated_at"]) == release.released_at
            except BaseException as error:
                errors.append(error)
        if case.store is not None:
            try:
                assert _empty_financial_rows(case) == case.initial_financial
                assert _rows(case, daily.CONTROL_TABLES) == case.expected_control
                assert case.producer.calls == [] and case.accounting_calls == []
            except BaseException as error:
                errors.append(error)
        try:
            assert all(connection.closed for connection in case.connections)
        except BaseException as error:
            errors.append(error)
        else:
            try:
                case.engine.dispose()
                case.disposed = True
            except BaseException as error:
                errors.append(error)
    if errors:
        raise BaseExceptionGroup(
            "component fixture and cleanup failed", ([primary] if primary else []) + errors
        )


@pytest.fixture
def case(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'bounded-control.sqlite'}")
    value = SimpleNamespace(
        engine=engine,
        clock=MutableClock(_AT),
        producer=_UnusedProducer(),
        accounting=PersonalAccounting(),
        coordinator=None,
        policy=None,
        controls=None,
        store=None,
        r1=None,
        expected_lease=None,
        expected_leases=[],
        initial_financial=None,
        expected_control=None,
        connections=[],
        sql=[],
        listeners=[],
        accounting_calls=[],
        replays=[],
        threads=[],
        worker_errors=[],
        barriers=[],
        replay_barrier=None,
        reader_thread=None,
        disposed=False,
    )
    with _observe(value):
        primary = None
        try:
            # Fresh component tables only: no migration/readiness qualification.
            metadata.create_all(engine)
            value.policy = AccountLeasePolicy(
                "bounded-control-component",
                "1",
                timedelta(seconds=60),
                timedelta(seconds=5),
                timedelta(seconds=10),
            )
            value.coordinator = SqlAccountCoordinator(
                account_id=_ACCOUNT,
                authority=SqlAccountCoordinatorAuthority(
                    engine=engine, policy=value.policy, clock=value.clock
                ),
            )
            value.r1 = value.coordinator.acquire("component-owner")
            value.expected_lease = value.r1
            value.expected_leases.append(value.r1)
            value.controls = SqlOperationalControlRepository(engine=engine, clock=value.clock)
            value.initial = value.controls.apply(
                _command(value, OperationalControlCommandKind.INITIALIZE_HALTED, "initial-halt")
            )
            assert value.initial.effective_state is OperationalControlState.HALTED
            value.store = _store(value)
            value.initial_financial = _empty_financial_rows(value)
            value.expected_control = _rows(value, daily.CONTROL_TABLES)
            yield value
        except BaseException as error:
            primary = error
            raise
        finally:
            _cleanup(value, primary)
    assert value.disposed


def _capture(case):
    offset = len(case.connections)
    raw = case.store.read_snapshot(account_id=_ACCOUNT, fence=case.r1.fence)
    captured = case.connections[offset:]
    assert len(captured) >= 2 and all(connection.closed for connection in captured)
    assert tuple(value.table for value in raw.tables) == (
        *DAILY_RUNTIME_TABLES,
        *daily.CONTROL_TABLES,
    )
    assert raw.producer.tables == () and raw.attempt_sources is raw.observed_sources is None
    assert raw.capture_usage[0] == sum(len(value.rows) for value in raw.tables)
    for actual, maximum in zip(
        raw.capture_usage,
        (daily.MAX_TOTAL_ROWS, daily.MAX_TOTAL_BYTES, daily.MAX_METADATA_BYTES),
        strict=True,
    ):
        assert type(actual) is int and 0 <= actual <= maximum
    return raw


def _resolve(case, raw):
    assert all(connection.closed for connection in case.connections)
    offset = len(case.sql)
    result = case.store.resolve_snapshot(raw)
    case.store.require_resolved_snapshot(result)
    assert case.sql[offset:] == []
    assert result.raw is raw and result.assignment is None
    assert result.assignment_rows == result.admissions == result.attempts == ()
    assert result.obligations.bindings == () and result.observed_groups == ()
    return result


def _receipt(receipt, lease, *, not_before):
    assert type(receipt) is AccountFenceReceipt
    assert receipt.fence == lease.fence
    assert receipt.lease_sha256 == lease.semantic_sha256
    assert receipt.policy_sha256 == lease.policy_sha256
    assert receipt.valid_until == lease.expires_at
    assert not_before <= receipt.validated_at < receipt.valid_until
    assert lease.heartbeat_at <= receipt.validated_at


def test_owned_halted_control_capture_replays_and_rechecks(case):
    raw = _capture(case)
    resolved = _resolve(case, raw)
    tables = {
        value.table: daily._typed_rows(value)
        for value in raw.tables
        if any(value.table is selected for selected in daily.CONTROL_TABLES)
    }
    assert tuple(tables) == daily.CONTROL_TABLES
    transitions, completions, heads = (tables[table] for table in daily.CONTROL_TABLES)
    assert len(transitions) == len(heads) == 1 and completions == ()
    assert all(connection.closed for connection in case.connections)
    offset = len(case.sql)
    replayed = resolve_operational_control_rows(
        account_id=_ACCOUNT,
        transition_rows=tuple(sorted(transitions, key=lambda row: row["sequence_number"])),
        completion_rows=completions,
        head_row=heads[0],
    )
    assert case.sql[offset:] == []
    assert replayed == resolved.control == case.controls.load(_ACCOUNT) == case.initial
    assert replayed.effective_state is OperationalControlState.HALTED
    assert len(replayed.blocking_events) == 1 and not replayed.blocker_overflowed
    assert case.replays == [threading.current_thread(), threading.current_thread()]
    case.clock.advance(timedelta(milliseconds=100))
    with _write_transaction(case.engine) as connection:
        receipt = case.store.recheck_snapshot_in_transaction(
            connection, resolved, fence=case.r1.fence
        )
    _receipt(receipt, case.r1, not_before=raw.receipt.validated_at)
    assert receipt.validated_at == case.clock.instant
    assert receipt.validated_at > raw.receipt.validated_at
    assert _rows(case, daily.CONTROL_TABLES) == case.expected_control
    assert _empty_financial_rows(case) == case.initial_financial


@pytest.mark.parametrize("kind", ["raw-copy", "raw-foreign", "resolved-copy", "resolved-foreign"])
def test_copy_or_foreign_control_snapshot_has_no_ownership(case, kind):
    raw = _capture(case)
    resolved = _resolve(case, raw)
    foreign = _store(case)
    before = _rows(case, (*daily.CONTROL_TABLES, phase2_account_leases, phase2_account_lease_heads))
    if kind == "raw-copy":
        with pytest.raises(daily.DailyRuntimeRiskConflict, match=_OWNER_ERROR):
            case.store.resolve_snapshot(replace(raw))
    elif kind == "raw-foreign":
        with pytest.raises(daily.DailyRuntimeRiskConflict, match=_OWNER_ERROR):
            foreign.resolve_snapshot(raw)
    else:
        owner, value = (
            (case.store, replace(resolved)) if kind == "resolved-copy" else (foreign, resolved)
        )
        with (
            pytest.raises(daily.DailyRuntimeRiskConflict, match=_OWNER_ERROR),
            _write_transaction(case.engine) as connection,
        ):
            owner.recheck_snapshot_in_transaction(connection, value, fence=case.r1.fence)
    assert (
        _rows(case, (*daily.CONTROL_TABLES, phase2_account_leases, phase2_account_lease_heads))
        == before
    )
    assert _empty_financial_rows(case) == case.initial_financial
    assert case.producer.calls == [] and case.accounting_calls == []


def test_control_writer_commits_during_detached_replay_and_recheck_denies_old_head(case):
    raw = _capture(case)
    entered, release, read_done, write_done = (threading.Event() for _ in range(4))
    case.barriers.append(release)
    case.replay_barrier = (entered, release)
    results, changed = [], []

    def read():
        try:
            results.append(case.store.resolve_snapshot(raw))
        except BaseException as error:
            case.worker_errors.append(error)
        finally:
            read_done.set()

    def write():
        try:
            changed.append(
                case.controls.apply(
                    _command(case, OperationalControlCommandKind.HALT, "later-halt")
                )
            )
        except BaseException as error:
            case.worker_errors.append(error)
        finally:
            write_done.set()

    reader = threading.Thread(target=read, name="detached-control-reader")
    writer = threading.Thread(target=write, name="halted-control-writer")
    case.reader_thread = reader
    case.threads.extend((reader, writer))
    case.clock.advance(timedelta(milliseconds=100))
    sql_offset = len(case.sql)
    reader.start()
    try:
        assert entered.wait(5) and not read_done.is_set()
        writer.start()
        assert write_done.wait(5) and not read_done.is_set()
        assert not release.is_set() and case.worker_errors == []
        assert len(changed) == 1 and changed[0].sequence_number == case.initial.sequence_number + 1
        assert changed[0].effective_state is OperationalControlState.HALTED
    finally:
        release.set()
        reader.join(10)
        if writer.ident is not None:
            writer.join(10)
        case.replay_barrier = None
    assert not reader.is_alive() and not writer.is_alive() and case.worker_errors == []
    assert read_done.is_set() and len(results) == 1
    assert not any(thread is reader for _, _, thread in case.sql[sql_offset:])
    resolved = results[0]
    case.store.require_resolved_snapshot(resolved)
    assert resolved.raw is raw and resolved.control == case.initial
    assert case.controls.load(_ACCOUNT) == changed[0]
    case.expected_control = _rows(case, daily.CONTROL_TABLES)
    before = _rows(case, (phase2_account_leases, phase2_account_lease_heads))
    with (
        pytest.raises(daily.DailyRuntimeRiskConflict, match="captured row inventory changed"),
        _write_transaction(case.engine) as connection,
    ):
        case.store.recheck_snapshot_in_transaction(connection, resolved, fence=case.r1.fence)
    assert _rows(case, (phase2_account_leases, phase2_account_lease_heads)) == before
    assert _rows(case, daily.CONTROL_TABLES) == case.expected_control
    assert _empty_financial_rows(case) == case.initial_financial


@pytest.mark.parametrize("mode", ["rows", "metadata"])
def test_existing_control_capture_budget_denies_before_transfer(case, mode):
    budget = (
        daily.RuntimeReadBudget(rows=daily.MAX_TOTAL_ROWS)
        if mode == "rows"
        else daily.RuntimeReadBudget(metadata_bytes=daily.MAX_METADATA_BYTES)
    )
    table = daily.CONTROL_TABLES[0]
    offset = len(case.sql)
    with (
        pytest.raises(
            daily.DailyRuntimeRiskConflict, match="daily aggregate capture bound exceeded"
        ),
        _write_transaction(case.engine) as connection,
    ):
        daily.capture_runtime_table(connection, table, account_id=_ACCOUNT, budget=budget)
    queries = [text for _, text, _ in case.sql[offset:] if table.name in text]
    assert len(queries) == 1 and "count(" in queries[0].lower()
    assert budget.captured == []
    assert _rows(case, daily.CONTROL_TABLES) == case.expected_control
    assert _empty_financial_rows(case) == case.initial_financial


def test_existing_b_recheck_can_report_same_fence_r2(case):
    raw = _capture(case)
    resolved = _resolve(case, raw)
    retained = raw.receipt
    case.clock.advance(timedelta(milliseconds=500))
    # One deliberate adverse fixture revision. B itself never renews or adopts.
    r2 = case.coordinator.renew(case.r1.fence)
    case.expected_lease = r2
    case.expected_leases.append(r2)
    assert r2.revision_number == 2 and r2.previous_lease_sha256 == case.r1.semantic_sha256
    assert r2.fence == case.r1.fence and r2.policy_sha256 == case.r1.policy_sha256
    assert r2.expires_at - r2.heartbeat_at == case.policy.lease_ttl == timedelta(seconds=60)
    assert case.policy.maximum_in_flight_duration == timedelta(seconds=5)
    assert case.policy.takeover_safety_interval == timedelta(seconds=10)
    with _write_transaction(case.engine) as connection:
        current = case.store.recheck_snapshot_in_transaction(
            connection, resolved, fence=case.r1.fence
        )
    _receipt(current, r2, not_before=retained.validated_at)
    assert current.lease_sha256 != retained.lease_sha256
    assert raw.receipt is retained and resolved.raw is raw
    assert retained.lease_sha256 == case.r1.semantic_sha256
    assert current.fence == retained.fence
    assert _rows(case, daily.CONTROL_TABLES) == case.expected_control
    assert _empty_financial_rows(case) == case.initial_financial
