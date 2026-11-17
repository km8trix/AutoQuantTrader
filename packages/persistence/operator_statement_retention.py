"""Private fixed statement transaction owned by the original continuous account.

No HTTP, re-arm, lease management, caller transaction, or arbitrary finalizer.
Persistence admits supplied authentication bounds; only app composition authenticates.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import UTC, datetime
from threading import current_thread
from typing import TYPE_CHECKING
from weakref import finalize

from sqlalchemy import Connection

from packages.application.operational_control_operator_journal import (
    operator_statement_journal_append,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.continuous_engine_contracts import ContinuousEngineSpec
from packages.domain.durable_journal_contracts import JournalHead
from packages.domain.operational_control import OperationalControlState
from packages.domain.operational_control_operator_record import (
    OperationalControlOperatorStatementRecord,
)
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    SqlDailyRuntimeRisk,
)
from packages.persistence.durable_journal import (
    ClassifiedJournalAppend,
    PreparedJournalAppend,
    SqlDurableJournal,
)

if TYPE_CHECKING:
    from packages.persistence.continuous_account import (
        ResolvedContinuousAccount,
        SqlContinuousAccount,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, repr=False)
class StatementCandidate:
    account: ResolvedContinuousAccount
    risk: ResolvedDailyRuntimeSnapshot
    daily: SqlDailyRuntimeRisk
    journal: SqlDurableJournal
    append: PreparedJournalAppend
    session_expires_at: datetime
    prepared_at: datetime
    r1: tuple[AccountFence, str, str, datetime]
    configuration: tuple[object, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False, repr=False)
class PreparedStatementWrite:
    candidate: StatementCandidate
    authenticated_at: datetime
    expires_at: datetime
    clock: object
    thread: object


@dataclass(frozen=True, slots=True, repr=False)
class StatementWriteOutcome:
    record_origin: str
    statement_retention: str
    invocation_commit: str
    cleanup: str
    primary: BaseException | None = None
    cleanup_errors: tuple[BaseException, ...] = ()


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError("STATEMENT_EXACT_UTC_REQUIRED")
    return value


def _graph(
    owner: SqlContinuousAccount, daily: SqlDailyRuntimeRisk, journal: SqlDurableJournal
) -> tuple[object, ...]:
    from packages.persistence.continuous_composition import SqlContinuousCommitComposer

    if type(owner.composer) is not SqlContinuousCommitComposer:
        raise ValueError("STATEMENT_EXACT_COMPOSER_REQUIRED")
    return (
        owner,
        owner.engine,
        owner.coordinator,
        owner.coordinator._authority,
        owner.coordinator._authority._engine,
        owner.coordinator._authority.policy,
        owner.coordinator._authority.clock,
        owner.journal,
        owner.codec,
        owner.artifacts,
        owner.composer,
        owner.composer.engine,
        owner.composer.coordinator,
        owner.composer.daily,
        owner.composer.producer_history,
        daily,
        daily.engine,
        daily.coordinator,
        daily.producers,
        journal,
        journal._engine,
        journal._codec,
    )


def _lease(receipt: AccountFenceReceipt) -> tuple[AccountFence, str, str, datetime]:
    return (receipt.fence, receipt.lease_sha256, receipt.policy_sha256, receipt.valid_until)


def _remember(
    owner: SqlContinuousAccount, value: StatementCandidate | PreparedStatementWrite
) -> None:
    owner._statement_values[id(value)] = value
    owner._statement_fields[id(value)] = tuple(getattr(value, f.name) for f in fields(value))
    finalize(value, owner._statement_fields.pop, id(value), None)


def _require(
    owner: SqlContinuousAccount, value: StatementCandidate | PreparedStatementWrite, expected: type
) -> None:
    if type(value) is not expected or owner._statement_values.get(id(value)) is not value:
        raise ValueError("ORIGINAL_STATEMENT_OPERATION_REQUIRED")
    original = owner._statement_fields.get(id(value))
    actual = tuple(getattr(value, f.name) for f in fields(value))
    if original is None or any(a is not b for a, b in zip(actual, original, strict=True)):
        raise ValueError("STATEMENT_OPERATION_CHANGED")


def prepare_candidate(
    owner: SqlContinuousAccount,
    *,
    account: ResolvedContinuousAccount,
    risk: ResolvedDailyRuntimeSnapshot,
    daily: SqlDailyRuntimeRisk,
    journal: SqlDurableJournal,
    record: OperationalControlOperatorStatementRecord,
    expected_head: JournalHead,
    prepared_at: datetime,
) -> StatementCandidate:
    from packages.persistence.continuous_account import SqlContinuousAccount
    from packages.persistence.continuous_composition import SqlContinuousCommitComposer

    if (
        type(owner) is not SqlContinuousAccount
        or type(daily) is not SqlDailyRuntimeRisk
        or type(journal) is not SqlDurableJournal
    ):
        raise ValueError("STATEMENT_EXACT_OWNERS_REQUIRED")
    if (
        type(owner.composer) is not SqlContinuousCommitComposer
        or owner.engine is not daily.engine
        or owner.engine is not journal._engine
        or owner.coordinator is not daily.coordinator
        or owner.composer.engine is not owner.engine
        or owner.composer.coordinator is not owner.coordinator
        or owner.composer.daily is not daily
        or owner.composer.producer_history is not daily.producers
        or getattr(daily.producers, "accounts", None) is not owner
        or owner.codec is not journal._codec
    ):
        raise ValueError("STATEMENT_OWNER_GRAPH_DIFFERS")
    owner.require_resolved(account)
    daily.require_resolved_snapshot(risk)
    scope = account.receipt.commit.scope
    spec = account.checkpoint.inputs.spec
    if type(spec) is not ContinuousEngineSpec:
        raise ValueError("STATEMENT_CONTINUOUS_SPEC_REQUIRED")
    if (
        (scope.account_id, scope.account_binding_sha256, scope.stream_id, scope.environment)
        != (spec.account_id, spec.account_binding_sha256, spec.deployment_id, spec.environment)
        or scope.environment != "stateful_simulation"
        or spec.live_authorized is not False
    ):
        raise ValueError("STATEMENT_ACCOUNT_SCOPE_DIFFERS")
    control, statement = risk.control, record.statement
    if control is None or control.effective_state is not OperationalControlState.HALTED:
        raise ValueError("STATEMENT_HALTED_CONTROL_REQUIRED")
    if (
        risk.raw.account_id != scope.account_id
        or (
            statement.scope_id,
            statement.control_transition_id,
            statement.control_transition_sha256,
            statement.control_sequence_number,
            statement.control_state,
            statement.control_state_epoch_id,
        )
        != (
            scope.account_id,
            control.transition_id,
            control.semantic_sha256,
            control.sequence_number,
            control.effective_state,
            control.state_epoch_id,
        )
        or statement.blocking_event not in control.blocking_events
    ):
        raise ValueError("STATEMENT_CONTROL_SCOPE_DIFFERS")
    key, append = operator_statement_journal_append(scope, record, expected_head=expected_head)
    prepared = journal.prepare_append(key, append)
    value = StatementCandidate(
        account,
        risk,
        daily,
        journal,
        prepared,
        _utc(record.session_expires_at),
        _utc(prepared_at),
        _lease(risk.raw.receipt),
        _graph(owner, daily, journal),
    )
    _remember(owner, value)
    return value


def prepare_write(
    owner: SqlContinuousAccount,
    candidate: StatementCandidate,
    *,
    authenticated_at: datetime,
    expires_at: datetime,
    clock: object,
) -> PreparedStatementWrite:
    _require(owner, candidate, StatementCandidate)
    authenticated_at, expires_at = _utc(authenticated_at), _utc(expires_at)
    if (
        expires_at != candidate.session_expires_at
        or not candidate.prepared_at <= authenticated_at < expires_at
        or clock is not owner.coordinator._authority.clock
        or any(
            a is not b
            for a, b in zip(
                _graph(owner, candidate.daily, candidate.journal),
                candidate.configuration,
                strict=True,
            )
        )
    ):
        raise ValueError("STATEMENT_ADMISSION_BINDING_DIFFERS")
    # Consume candidate before issuing a one-invocation request.
    owner._statement_values.pop(id(candidate))
    value = PreparedStatementWrite(candidate, authenticated_at, expires_at, clock, current_thread())
    _remember(owner, value)
    return value


def retain(owner: SqlContinuousAccount, request: PreparedStatementWrite) -> StatementWriteOutcome:
    # No two requests may run simultaneously on this owner. A consumed request can
    # never be retried, including after an unknown COMMIT or failed delivery.
    if not owner._statement_write_lock.acquire(blocking=False):
        raise ValueError("STATEMENT_OPERATION_BUSY")
    connection = None
    token = ticket = None
    origin, retention, commit_state = "not_established", "not_established", "not_attempted"
    primary = None
    cleanup_errors: list[BaseException] = []
    try:
        _require(owner, request, PreparedStatementWrite)
        owner._statement_values.pop(id(request))
        if request.thread is not current_thread():
            raise ValueError("STATEMENT_OPERATION_THREAD_CHANGED")
        candidate = request.candidate
        original = owner._statement_fields.get(id(candidate))
        if original is None or any(
            getattr(candidate, f.name) is not item
            for f, item in zip(fields(candidate), original, strict=True)
        ):
            raise ValueError("STATEMENT_CANDIDATE_CHANGED")
        if any(
            a is not b
            for a, b in zip(
                _graph(owner, candidate.daily, candidate.journal),
                candidate.configuration,
                strict=True,
            )
        ):
            raise ValueError("STATEMENT_OWNER_GRAPH_CHANGED")
        # Original graph validation remains outside SQL.
        owner.require_resolved(candidate.account)
        candidate.daily.require_resolved_snapshot(candidate.risk)
        token = owner._begin_cooperative_write()
        connection = owner.engine.connect()
        if type(connection) is not Connection:
            raise ValueError("STATEMENT_EXACT_CONNECTION_REQUIRED")
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
            connection.begin()
        else:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        transaction = connection.get_transaction()
        owner._write_connections[id(connection)] = (connection, transaction)
        owner._mutation_connection(connection)
        checked = candidate.daily.recheck_snapshot_in_transaction(
            connection, candidate.risk, fence=candidate.r1[0]
        )
        if _lease(checked) != candidate.r1:
            raise ValueError("STATEMENT_EXACT_OPERATION_LEASE_REQUIRED")
        owner.recheck_in_transaction(connection, candidate.account, require_current=True)
        appended = candidate.journal.append_classified_in_transaction(connection, candidate.append)
        if type(appended) is not ClassifiedJournalAppend or appended.disposition not in (
            "inserted_in_this_transaction",
            "already_retained",
        ):
            raise ValueError("STATEMENT_JOURNAL_OUTCOME_INVALID")
        fresh = appended.disposition == "inserted_in_this_transaction"
        origin = "fresh_candidate" if fresh else "already_retained"
        if not fresh:
            retention = "verified_historical"
        candidate.journal.recheck_prepared_append_in_transaction(
            connection, candidate.append, require_current_head=fresh
        )
        checked = candidate.daily.recheck_snapshot_in_transaction(
            connection, candidate.risk, fence=candidate.r1[0]
        )
        if _lease(checked) != candidate.r1:
            raise ValueError("STATEMENT_EXACT_OPERATION_LEASE_REQUIRED")
        owner.recheck_in_transaction(connection, candidate.account, require_current=True)
        ticket = owner.coordinator.prepare_commit_admission_in_transaction(
            connection, candidate.r1[0]
        )
        if _lease(ticket.receipt) != candidate.r1:
            raise ValueError("STATEMENT_EXACT_OPERATION_LEASE_REQUIRED")
        if any(
            a is not b
            for a, b in zip(
                _graph(owner, candidate.daily, candidate.journal),
                candidate.configuration,
                strict=True,
            )
        ):
            raise ValueError("STATEMENT_OWNER_GRAPH_CHANGED")
        for value in (request, candidate):
            baseline = owner._statement_fields.get(id(value))
            if baseline is None or any(
                getattr(value, f.name) is not original
                for f, original in zip(fields(value), baseline, strict=True)
            ):
                raise ValueError("STATEMENT_OPERATION_CHANGED")
        owner._mutation_connection(connection)
        owner._check_cooperative_write(token)
        native_commit = connection.commit
        owner.coordinator.finish_commit_admission(
            ticket,
            lower_bounds=(
                candidate.prepared_at,
                request.authenticated_at,
                candidate.risk.raw.receipt.validated_at,
                checked.validated_at,
            ),
            deadlines=(request.expires_at, candidate.r1[3]),
        )
        # Only assignments and the bound native COMMIT follow the final sample.
        commit_state = "unknown"
        if fresh:
            retention = "unknown"
        native_commit()
        commit_state = "returned_successfully"
        if fresh:
            retention = "committed_fresh"
    except BaseException as error:
        primary = error
        if connection is not None and commit_state == "not_attempted":
            try:
                connection.rollback()
                if connection.in_transaction() or (
                    connection.dialect.name == "sqlite"
                    and getattr(connection.connection.driver_connection, "in_transaction", True)
                ):
                    raise ValueError("STATEMENT_ROLLBACK_INCOMPLETE")
                commit_state = "failed_before_attempt_with_rollback"
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
    finally:
        if ticket is not None:
            try:
                owner.coordinator.invalidate_commit_admission(ticket)
            except BaseException as error:
                cleanup_errors.append(error)
        if connection is not None:
            owner._write_connections.pop(id(connection), None)
            try:
                connection.close()
                if not connection.closed:
                    raise ValueError("STATEMENT_CONNECTION_NOT_CLOSED")
            except BaseException as error:
                cleanup_errors.append(error)
        if token is not None:
            try:
                owner._finish_cooperative_write(token)
            except BaseException as error:
                cleanup_errors.append(error)
        owner._statement_write_lock.release()
    return StatementWriteOutcome(
        origin,
        retention,
        commit_state,
        "failed" if cleanup_errors else "verified_complete",
        primary,
        tuple(cleanup_errors),
    )
