"""Durable, account-serialized broker request-budget admission."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetError,
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitConflict,
    BrokerRequestPermitFreshnessReceipt,
    BrokerRequestPurpose,
    _broker_request_permit_freshness_receipt,
    issue_broker_request_permit,
    require_fresh_broker_request_permit,
)
from packages.domain.clock import Clock
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import ImmutableFactConflict, as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase4_broker_request_heads,
    phase4_broker_request_permits,
)

BrokerRequestBudgetRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


@dataclass(frozen=True, slots=True)
class _PersistedBrokerRequestPermit:
    policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    window_permit_count: int
    admission_ceiling: int


@dataclass(frozen=True, slots=True)
class _BrokerRequestHead:
    account_id: str
    last_sequence_number: int
    last_permit_sha256: str
    last_issued_at: datetime


def _duration_seconds(value: timedelta) -> int:
    if value.microseconds != 0:
        raise BrokerRequestBudgetError("broker request duration must use exact whole seconds")
    return value.days * 86_400 + value.seconds


def _required_text(row: BrokerRequestBudgetRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise BrokerRequestBudgetError(f"persisted broker request {field_name} must be a string")
    return value


def _optional_text(row: BrokerRequestBudgetRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise BrokerRequestBudgetError(
            f"persisted broker request {field_name} must be a string or null"
        )
    return value


def _required_integer(row: BrokerRequestBudgetRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise BrokerRequestBudgetError(f"persisted broker request {field_name} must be an integer")
    return value


def _optional_integer(
    row: BrokerRequestBudgetRow,
    field_name: str,
) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise BrokerRequestBudgetError(
            f"persisted broker request {field_name} must be an integer or null"
        )
    return value


def _required_datetime(row: BrokerRequestBudgetRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise BrokerRequestBudgetError(f"persisted broker request {field_name} must be a datetime")
    return as_aware_utc(value)


def _policy_from_row(row: BrokerRequestBudgetRow) -> BrokerRequestBudgetPolicy:
    return BrokerRequestBudgetPolicy(
        policy_id=_required_text(row, "policy_id"),
        policy_version=_required_text(row, "policy_version"),
        provider_id=_required_text(row, "provider_id"),
        environment=_required_text(row, "environment"),
        window_duration=timedelta(seconds=_required_integer(row, "window_seconds")),
        permit_ttl=timedelta(seconds=_required_integer(row, "permit_ttl_seconds")),
        submission_capacity=_required_integer(row, "submission_capacity"),
        recovery_capacity=_required_integer(row, "recovery_capacity"),
        total_capacity=_required_integer(row, "total_capacity"),
    )


def _demand_from_row(row: BrokerRequestBudgetRow) -> BrokerRequestDemand:
    try:
        purpose = BrokerRequestPurpose(_required_text(row, "purpose"))
    except ValueError as error:
        raise BrokerRequestBudgetError("persisted broker request purpose is unsupported") from error
    return BrokerRequestDemand(
        account_id=_required_text(row, "account_id"),
        idempotency_key=_required_text(row, "idempotency_key"),
        operation=_required_text(row, "operation"),
        purpose=purpose,
        correlation_sha256=_required_text(row, "correlation_sha256"),
        requested_at=_required_datetime(row, "requested_at"),
    )


def broker_request_permit_from_row(
    row: BrokerRequestBudgetRow,
) -> _PersistedBrokerRequestPermit:
    """Strictly decode and authenticate one persisted permit and its inputs."""

    try:
        policy = _policy_from_row(row)
        demand = _demand_from_row(row)
        permit = BrokerRequestPermit(
            account_id=_required_text(row, "account_id"),
            purpose=demand.purpose,
            demand_id=_required_text(row, "demand_id"),
            demand_sha256=_required_text(row, "demand_sha256"),
            policy_sha256=_required_text(row, "policy_sha256"),
            sequence_number=_required_integer(row, "sequence_number"),
            previous_permit_sha256=_optional_text(
                row,
                "previous_permit_sha256",
            ),
            issued_at=_required_datetime(row, "issued_at"),
            expires_at=_required_datetime(row, "expires_at"),
        )
        require_fresh_broker_request_permit(
            permit=permit,
            policy=policy,
            demand=demand,
            checked_at=permit.issued_at,
        )
        previous_sequence_number = _optional_integer(
            row,
            "previous_sequence_number",
        )
        expected_previous_sequence = (
            None if permit.sequence_number == 1 else permit.sequence_number - 1
        )
        if previous_sequence_number != expected_previous_sequence:
            raise BrokerRequestBudgetError("persisted broker request previous sequence conflicts")
        window_permit_count = _required_integer(row, "window_permit_count")
        admission_ceiling = _required_integer(row, "admission_ceiling")
        if window_permit_count <= 0 or window_permit_count > admission_ceiling:
            raise BrokerRequestBudgetError(
                "persisted broker request rolling count exceeds its admission ceiling"
            )
        if admission_ceiling != policy.capacity_for(demand.purpose):
            raise BrokerRequestBudgetError(
                "persisted broker request admission ceiling conflicts with policy"
            )
        duplicated_values: tuple[tuple[str, object], ...] = (
            ("permit_id", permit.permit_id),
            ("policy_payload", policy.canonical_json),
            ("policy_sha256", policy.semantic_sha256),
            ("demand_id", demand.demand_id),
            ("demand_payload", demand.canonical_json),
            ("demand_sha256", demand.semantic_sha256),
            ("canonical_payload", permit.canonical_json),
            ("semantic_sha256", permit.semantic_sha256),
        )
        for field_name, expected in duplicated_values:
            if row[field_name] != expected:
                raise BrokerRequestBudgetError(f"persisted broker request {field_name} conflicts")
        return _PersistedBrokerRequestPermit(
            policy=policy,
            demand=demand,
            permit=permit,
            window_permit_count=window_permit_count,
            admission_ceiling=admission_ceiling,
        )
    except BrokerRequestBudgetError:
        raise
    except (KeyError, OverflowError, TypeError, ValueError) as error:
        raise BrokerRequestBudgetError("persisted broker request permit is malformed") from error


def immutable_broker_request_permit_values(
    *,
    policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    window_permit_count: int,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one permit."""

    if type(policy) is not BrokerRequestBudgetPolicy:
        raise BrokerRequestBudgetError("broker request persistence requires an exact budget policy")
    if type(demand) is not BrokerRequestDemand:
        raise BrokerRequestBudgetError("broker request persistence requires an exact demand")
    if type(permit) is not BrokerRequestPermit:
        raise BrokerRequestBudgetError("broker request persistence requires an exact permit")
    policy.__post_init__()
    demand.__post_init__()
    permit.__post_init__()
    require_fresh_broker_request_permit(
        permit=permit,
        policy=policy,
        demand=demand,
        checked_at=permit.issued_at,
    )
    admission_ceiling = policy.capacity_for(demand.purpose)
    if (
        type(window_permit_count) is not int
        or window_permit_count <= 0
        or window_permit_count > admission_ceiling
    ):
        raise BrokerRequestBudgetError(
            "broker request rolling count must fit its admission ceiling"
        )
    return {
        "permit_id": permit.permit_id,
        "account_id": permit.account_id,
        "sequence_number": permit.sequence_number,
        "previous_sequence_number": (
            None if permit.sequence_number == 1 else permit.sequence_number - 1
        ),
        "previous_permit_sha256": permit.previous_permit_sha256,
        "provider_id": policy.provider_id,
        "environment": policy.environment,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "window_seconds": _duration_seconds(policy.window_duration),
        "permit_ttl_seconds": _duration_seconds(policy.permit_ttl),
        "submission_capacity": policy.submission_capacity,
        "recovery_capacity": policy.recovery_capacity,
        "total_capacity": policy.total_capacity,
        "policy_payload": policy.canonical_json,
        "policy_sha256": policy.semantic_sha256,
        "demand_id": demand.demand_id,
        "idempotency_key": demand.idempotency_key,
        "operation": demand.operation,
        "purpose": demand.purpose.value,
        "correlation_sha256": demand.correlation_sha256,
        "requested_at": demand.requested_at,
        "demand_payload": demand.canonical_json,
        "demand_sha256": demand.semantic_sha256,
        "issued_at": permit.issued_at,
        "expires_at": permit.expires_at,
        "window_permit_count": window_permit_count,
        "admission_ceiling": admission_ceiling,
        "canonical_payload": permit.canonical_json,
        "semantic_sha256": permit.semantic_sha256,
    }


def _head_from_row(row: BrokerRequestBudgetRow) -> _BrokerRequestHead:
    try:
        head = _BrokerRequestHead(
            account_id=_required_text(row, "account_id"),
            last_sequence_number=_required_integer(row, "last_sequence_number"),
            last_permit_sha256=_required_text(row, "last_permit_sha256"),
            last_issued_at=_required_datetime(row, "last_issued_at"),
        )
        if (
            not head.account_id
            or head.account_id != head.account_id.strip()
            or len(head.account_id) > 64
            or head.last_sequence_number <= 0
            or len(head.last_permit_sha256) != 64
            or any(character not in "0123456789abcdef" for character in head.last_permit_sha256)
        ):
            raise BrokerRequestBudgetError("persisted broker request head is malformed")
        return head
    except BrokerRequestBudgetError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerRequestBudgetError("persisted broker request head is malformed") from error


def _head(connection: Connection, account_id: str) -> _BrokerRequestHead | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_request_heads).where(
                phase4_broker_request_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _record_by_id(
    connection: Connection,
    permit_id: str,
) -> _PersistedBrokerRequestPermit | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_request_permits).where(
                phase4_broker_request_permits.c.permit_id == permit_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_request_permit_from_row(row)


def _record_by_semantic_sha256(
    connection: Connection,
    *,
    account_id: str,
    semantic_sha256: str,
) -> _PersistedBrokerRequestPermit | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_request_permits).where(
                phase4_broker_request_permits.c.account_id == account_id,
                phase4_broker_request_permits.c.semantic_sha256 == semantic_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_request_permit_from_row(row)


def _record_by_idempotency(
    connection: Connection,
    *,
    account_id: str,
    idempotency_key: str,
) -> _PersistedBrokerRequestPermit | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_request_permits).where(
                phase4_broker_request_permits.c.account_id == account_id,
                phase4_broker_request_permits.c.idempotency_key == idempotency_key,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_request_permit_from_row(row)


def _terminal_record(
    connection: Connection,
    head: _BrokerRequestHead,
) -> _PersistedBrokerRequestPermit:
    successor_exists = connection.scalar(
        sa.select(
            sa.exists().where(
                phase4_broker_request_permits.c.account_id == head.account_id,
                phase4_broker_request_permits.c.sequence_number > head.last_sequence_number,
            )
        )
    )
    if successor_exists:
        raise BrokerRequestBudgetError(
            "broker request head is rolled back from its terminal permit"
        )
    record = _record_by_semantic_sha256(
        connection,
        account_id=head.account_id,
        semantic_sha256=head.last_permit_sha256,
    )
    if (
        record is None
        or record.permit.sequence_number != head.last_sequence_number
        or record.permit.semantic_sha256 != head.last_permit_sha256
        or record.permit.issued_at != head.last_issued_at
    ):
        raise BrokerRequestBudgetError("broker request head conflicts with its terminal permit")
    return record


def _authenticate_record_position(
    connection: Connection,
    record: _PersistedBrokerRequestPermit,
) -> _BrokerRequestHead:
    records = _verified_history_records(connection, record.permit.account_id)
    if record not in records:
        raise BrokerRequestBudgetError(
            "broker request permit exists outside its authenticated history"
        )
    head = _head(connection, record.permit.account_id)
    if head is None:
        raise BrokerRequestBudgetError(
            "broker request permits exist without a durable account head"
        )
    return head


def _active_policy_records(
    connection: Connection,
    *,
    policy: BrokerRequestBudgetPolicy,
    previous_record: _PersistedBrokerRequestPermit,
    issued_at: datetime,
) -> tuple[_PersistedBrokerRequestPermit, ...]:
    try:
        accounting_duration = policy.window_duration + policy.permit_ttl
        lower_bound = issued_at - accounting_duration
    except OverflowError as error:
        raise BrokerRequestBudgetError(
            "broker request accounting horizon exceeds datetime range"
        ) from error
    rows = (
        connection.execute(
            sa.select(phase4_broker_request_permits)
            .where(
                phase4_broker_request_permits.c.account_id == previous_record.permit.account_id,
                phase4_broker_request_permits.c.sequence_number
                <= previous_record.permit.sequence_number,
                phase4_broker_request_permits.c.policy_sha256 == policy.semantic_sha256,
                phase4_broker_request_permits.c.issued_at >= lower_bound,
            )
            .limit(policy.total_capacity + 1)
        )
        .mappings()
        .all()
    )
    if len(rows) > policy.total_capacity:
        raise BrokerRequestBudgetError(
            "broker request active history exceeds the durable policy limit"
        )
    records = tuple(broker_request_permit_from_row(row) for row in rows)
    return tuple(sorted(records, key=lambda record: record.permit.sequence_number))


def _history_records(
    connection: Connection,
    account_id: str,
) -> tuple[_PersistedBrokerRequestPermit, ...]:
    rows = connection.execute(
        sa.select(phase4_broker_request_permits)
        .where(phase4_broker_request_permits.c.account_id == account_id)
        .order_by(phase4_broker_request_permits.c.sequence_number)
    ).mappings()
    return tuple(broker_request_permit_from_row(row) for row in rows)


def _validate_account_record_stream(
    *,
    account_id: str,
    records: Iterable[_PersistedBrokerRequestPermit],
    head: _BrokerRequestHead | None,
) -> None:
    previous: _PersistedBrokerRequestPermit | None = None
    active_records: deque[_PersistedBrokerRequestPermit] = deque()
    record_count = 0
    for expected_sequence, record in enumerate(records, start=1):
        record_count = expected_sequence
        permit = record.permit
        if permit.account_id != account_id:
            raise BrokerRequestBudgetError(
                "broker request history contains a permit for another account"
            )
        if permit.sequence_number != expected_sequence:
            raise BrokerRequestBudgetError(
                "broker request history is not a contiguous account-local sequence"
            )
        expected_predecessor = None if previous is None else previous.permit.semantic_sha256
        if permit.previous_permit_sha256 != expected_predecessor:
            raise BrokerRequestBudgetError("broker request history predecessor chain conflicts")
        if previous is not None and permit.issued_at < previous.permit.issued_at:
            raise BrokerRequestBudgetError(
                "broker request history contains a regressing issue clock"
            )
        if record.demand.requested_at > permit.issued_at:
            raise BrokerRequestBudgetError("broker request history contains issuance before demand")

        if previous is None:
            active_records.clear()
        elif record.policy.semantic_sha256 != previous.policy.semantic_sha256:
            if (
                record.policy.provider_id != previous.policy.provider_id
                or record.policy.environment != previous.policy.environment
            ):
                raise BrokerRequestBudgetError(
                    "broker request policy rotation changed provider or environment"
                )
            try:
                old_window_drained_at = previous.permit.expires_at + previous.policy.window_duration
            except OverflowError as error:
                raise BrokerRequestBudgetError(
                    "broker request policy window exceeds datetime range"
                ) from error
            if permit.issued_at <= old_window_drained_at:
                raise BrokerRequestBudgetError(
                    "broker request policy changed before the old rolling window drained"
                )
            active_records.clear()
        else:
            try:
                lower_bound = permit.issued_at - record.policy.window_duration
            except OverflowError as error:
                raise BrokerRequestBudgetError(
                    "broker request rolling window exceeds datetime range"
                ) from error
            while active_records and active_records[0].permit.expires_at < lower_bound:
                active_records.popleft()
        expected_count = len(active_records) + 1
        if record.window_permit_count != expected_count:
            raise BrokerRequestBudgetError(
                "broker request rolling count conflicts with durable history"
            )
        if expected_count > record.admission_ceiling:
            raise BrokerRequestBudgetError(
                "broker request history exceeds its purpose admission ceiling"
            )
        active_records.append(record)
        previous = record

    if record_count == 0:
        if head is not None:
            raise BrokerRequestBudgetError("broker request head exists without durable permits")
        return
    if head is None or previous is None:
        raise BrokerRequestBudgetError(
            "broker request permits exist without a durable account head"
        )
    terminal = previous.permit
    if head.last_sequence_number < terminal.sequence_number:
        raise BrokerRequestBudgetError(
            "broker request head is rolled back from its durable terminal permit"
        )
    if (
        head.account_id != account_id
        or head.last_sequence_number != terminal.sequence_number
        or head.last_permit_sha256 != terminal.semantic_sha256
        or head.last_issued_at != terminal.issued_at
    ):
        raise BrokerRequestBudgetError("broker request head conflicts with durable terminal permit")


def _validate_account_history(
    *,
    account_id: str,
    records: tuple[_PersistedBrokerRequestPermit, ...],
    head: _BrokerRequestHead | None,
) -> None:
    _validate_account_record_stream(
        account_id=account_id,
        records=records,
        head=head,
    )


def _verified_history_records(
    connection: Connection,
    account_id: str,
) -> tuple[_PersistedBrokerRequestPermit, ...]:
    records = _history_records(connection, account_id)
    _validate_account_history(
        account_id=account_id,
        records=records,
        head=_head(connection, account_id),
    )
    return records


def _verify_broker_request_budget_integrity(connection: Connection) -> None:
    """Authenticate every permit chain inside a caller-owned stable transaction."""

    permit_without_head = connection.scalar(
        sa.select(phase4_broker_request_permits.c.account_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_broker_request_heads.c.account_id
                    == phase4_broker_request_permits.c.account_id
                )
            )
        )
        .limit(1)
    )
    if permit_without_head is not None:
        raise BrokerRequestBudgetError("broker request permits exist without durable account heads")
    head_rows = connection.execute(
        sa.select(phase4_broker_request_heads)
        .order_by(phase4_broker_request_heads.c.account_id)
        .execution_options(yield_per=128)
    ).mappings()
    for row in head_rows:
        head = _head_from_row(row)
        permit_rows = connection.execute(
            sa.select(phase4_broker_request_permits)
            .where(phase4_broker_request_permits.c.account_id == head.account_id)
            .order_by(phase4_broker_request_permits.c.sequence_number)
            .execution_options(yield_per=256)
        ).mappings()
        _validate_account_record_stream(
            account_id=head.account_id,
            records=(broker_request_permit_from_row(permit_row) for permit_row in permit_rows),
            head=head,
        )


def verify_broker_request_budget_integrity(engine: Engine) -> None:
    """Authenticate all durable broker request permits in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise BrokerRequestBudgetError("broker request budget verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise BrokerRequestBudgetError(
            f"broker request budget verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_broker_request_budget_integrity(connection)


def _require_trusted_time(instant: datetime) -> None:
    if (
        type(instant) is not datetime
        or instant.tzinfo is None
        or instant.utcoffset() is None
        or instant.utcoffset() != UTC.utcoffset(instant)
    ):
        raise BrokerRequestBudgetError("broker request trusted time must be UTC")


class SqlBrokerRequestBudgetRepository:
    """Allocate immutable permits under the durable account transition lock."""

    __slots__ = ("_clock", "_engine")

    def __init__(self, *, engine: Engine, clock: Clock) -> None:
        if not isinstance(engine, Engine):
            raise BrokerRequestBudgetError("SQL broker request budget requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise BrokerRequestBudgetError(
                f"SQL broker request budget does not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise BrokerRequestBudgetError("SQL broker request budget requires a trusted clock")
        self._engine = engine
        self._clock = clock

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def issue(
        self,
        *,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        """Debit rolling capacity exactly once for one idempotent demand."""

        return self._issue(
            policy=policy,
            demand=demand,
            allow_exact_replay=True,
        )

    def issue_new(
        self,
        *,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        """Debit capacity only for a demand identity never admitted before."""

        return self._issue(
            policy=policy,
            demand=demand,
            allow_exact_replay=False,
        )

    def _issue(
        self,
        *,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
        allow_exact_replay: bool,
    ) -> BrokerRequestPermit:
        if type(policy) is not BrokerRequestBudgetPolicy:
            raise BrokerRequestBudgetError(
                "broker request issuance requires an exact budget policy"
            )
        if type(demand) is not BrokerRequestDemand:
            raise BrokerRequestBudgetError("broker request issuance requires an exact demand")
        policy.__post_init__()
        demand.__post_init__()
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, demand.account_id)
                issued_at = self._clock.now()
                _require_trusted_time(issued_at)
                history = _verified_history_records(connection, demand.account_id)
                previous_record = None if not history else history[-1]
                existing = _record_by_idempotency(
                    connection,
                    account_id=demand.account_id,
                    idempotency_key=demand.idempotency_key,
                )
                if existing is not None:
                    if existing.policy != policy or existing.demand != demand:
                        raise BrokerRequestPermitConflict(
                            "broker request idempotency identity conflicts with durable content"
                        )
                    if existing not in history:
                        raise BrokerRequestBudgetError(
                            "broker request permit exists outside its authenticated history"
                        )
                    if not allow_exact_replay:
                        raise BrokerRequestPermitConflict(
                            "broker request demand already has a durable permit"
                        )
                    return existing.permit

                previous_permit = None if previous_record is None else previous_record.permit
                if previous_permit is not None and issued_at < previous_permit.issued_at:
                    raise BrokerRequestPermitConflict(
                        "broker request issue clock moved backwards for the account"
                    )

                active_records: tuple[_PersistedBrokerRequestPermit, ...]
                if previous_record is None:
                    active_records = ()
                elif previous_record.policy.semantic_sha256 != policy.semantic_sha256:
                    try:
                        old_window_drained_at = (
                            previous_record.permit.expires_at
                            + previous_record.policy.window_duration
                        )
                    except OverflowError as error:
                        raise BrokerRequestBudgetError(
                            "broker request policy window exceeds datetime range"
                        ) from error
                    if issued_at <= old_window_drained_at:
                        raise BrokerRequestPermitConflict(
                            "broker request policy cannot change before the old "
                            "rolling window drains"
                        )
                    active_records = ()
                else:
                    active_records = _active_policy_records(
                        connection,
                        policy=policy,
                        previous_record=previous_record,
                        issued_at=issued_at,
                    )

                permit = issue_broker_request_permit(
                    policy=policy,
                    demand=demand,
                    issued_at=issued_at,
                    active_permits=tuple(record.permit for record in active_records),
                    previous_permit=previous_permit,
                    previous_policy=(None if previous_record is None else previous_record.policy),
                )
                window_permit_count = len(active_records) + 1
                values = immutable_broker_request_permit_values(
                    policy=policy,
                    demand=demand,
                    permit=permit,
                    window_permit_count=window_permit_count,
                )
                try:
                    connection.execute(sa.insert(phase4_broker_request_permits).values(**values))
                except IntegrityError as error:
                    raise BrokerRequestPermitConflict(
                        "broker request permit conflicts with durable history"
                    ) from error

                if previous_record is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_broker_request_heads).values(
                                account_id=demand.account_id,
                                last_sequence_number=permit.sequence_number,
                                last_permit_sha256=permit.semantic_sha256,
                                last_issued_at=permit.issued_at,
                            )
                        )
                    except IntegrityError as error:
                        raise BrokerRequestPermitConflict(
                            "broker request head conflicts with durable history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_broker_request_heads)
                        .where(
                            phase4_broker_request_heads.c.account_id == demand.account_id,
                            phase4_broker_request_heads.c.last_sequence_number
                            == previous_record.permit.sequence_number,
                            phase4_broker_request_heads.c.last_permit_sha256
                            == previous_record.permit.semantic_sha256,
                            phase4_broker_request_heads.c.last_issued_at
                            == previous_record.permit.issued_at,
                        )
                        .values(
                            last_sequence_number=permit.sequence_number,
                            last_permit_sha256=permit.semantic_sha256,
                            last_issued_at=permit.issued_at,
                        )
                    )
                    if updated.rowcount != 1:
                        raise BrokerRequestPermitConflict(
                            "broker request head changed during sequence allocation"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_broker_request_permits).where(
                            phase4_broker_request_permits.c.permit_id == permit.permit_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = broker_request_permit_from_row(row)
                if persisted != _PersistedBrokerRequestPermit(
                    policy=policy,
                    demand=demand,
                    permit=permit,
                    window_permit_count=window_permit_count,
                    admission_ceiling=policy.capacity_for(demand.purpose),
                ):
                    raise BrokerRequestBudgetError(
                        "broker request permit failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_broker_request_permits,
                    permit.permit_id,
                    row,
                    values,
                )
                persisted_head = _head(connection, demand.account_id)
                if (
                    persisted_head is None
                    or persisted_head.last_sequence_number != permit.sequence_number
                    or persisted_head.last_permit_sha256 != permit.semantic_sha256
                    or persisted_head.last_issued_at != permit.issued_at
                ):
                    raise BrokerRequestBudgetError("broker request head failed exact SQL readback")
                return persisted.permit
        except BrokerRequestBudgetError:
            raise
        except (AccountCoordinatorError, ImmutableFactConflict) as error:
            raise BrokerRequestBudgetError(str(error)) from error

    def require_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> None:
        """Authenticate durable freshness while preserving the legacy void API."""

        self.authenticate_fresh(
            permit=permit,
            policy=policy,
            demand=demand,
        )

    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: BrokerRequestBudgetPolicy,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermitFreshnessReceipt:
        """Authenticate durable admission and return trusted-clock evidence."""

        if type(permit) is not BrokerRequestPermit:
            raise BrokerRequestPermitConflict(
                "durable freshness requires an exact broker request permit"
            )
        if type(policy) is not BrokerRequestBudgetPolicy:
            raise BrokerRequestPermitConflict(
                "durable freshness requires an exact broker request policy"
            )
        if type(demand) is not BrokerRequestDemand:
            raise BrokerRequestPermitConflict(
                "durable freshness requires an exact broker request demand"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            record = _record_by_id(connection, permit.permit_id)
            if record is None:
                raise BrokerRequestPermitConflict(
                    "broker request permit has no durable admission record"
                )
            if record.permit != permit or record.policy != policy or record.demand != demand:
                raise BrokerRequestPermitConflict(
                    "durable broker request admission conflicts with supplied evidence"
                )
            _authenticate_record_position(connection, record)
            checked_at = self._clock.now()
            _require_trusted_time(checked_at)
            return _broker_request_permit_freshness_receipt(
                permit=permit,
                policy=policy,
                demand=demand,
                checked_at=checked_at,
            )

    def load(self, permit_id: str) -> BrokerRequestPermit | None:
        """Load one authenticated permit, or return ``None`` when absent."""

        if (
            type(permit_id) is not str
            or len(permit_id) != 64
            or any(character not in "0123456789abcdef" for character in permit_id)
        ):
            raise BrokerRequestBudgetError(
                "broker request permit ID must be a lowercase SHA-256 digest"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            record = _record_by_id(connection, permit_id)
            if record is None:
                return None
            _authenticate_record_position(connection, record)
            return record.permit

    def history(self, account_id: str) -> tuple[BrokerRequestPermit, ...]:
        """Return one authenticated account-local permit chain."""

        if (
            type(account_id) is not str
            or not account_id
            or account_id != account_id.strip()
            or len(account_id) > 64
        ):
            raise BrokerRequestBudgetError(
                "broker request account ID must be bounded, trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            return tuple(
                record.permit for record in _verified_history_records(connection, account_id)
            )


__all__ = [
    "SqlBrokerRequestBudgetRepository",
    "broker_request_permit_from_row",
    "immutable_broker_request_permit_values",
    "verify_broker_request_budget_integrity",
]
