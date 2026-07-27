"""Durable SQL journal for exact broker bytes captured before decoding."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.broker_ingress import (
    BROKER_INGRESS_CONTRACT_VERSION,
    BrokerIngressConflict,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
)
from packages.domain.canonical import canonical_json_text
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
)

BrokerIngressRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


@dataclass(frozen=True, slots=True)
class _BrokerIngressHead:
    account_id: str
    last_ingress_sequence: int
    last_receipt_sha256: str | None


def _receipt_payload(receipt: BrokerIngressReceipt) -> tuple[object, ...]:
    return (
        BROKER_INGRESS_CONTRACT_VERSION,
        "receipt",
        receipt.receipt_id,
        receipt.delivery.semantic_sha256,
        receipt.ingress_sequence,
        receipt.previous_receipt_sha256,
    )


def immutable_broker_ingress_values(
    receipt: BrokerIngressReceipt,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one raw receipt."""

    if type(receipt) is not BrokerIngressReceipt:
        raise BrokerIngressError(
            "broker ingress persistence requires an exact BrokerIngressReceipt"
        )
    receipt.__post_init__()
    delivery = receipt.delivery
    return {
        "receipt_id": receipt.receipt_id,
        "account_id": delivery.account_id,
        "ingress_sequence": receipt.ingress_sequence,
        "previous_receipt_sha256": receipt.previous_receipt_sha256,
        "delivery_idempotency_key": delivery.delivery_idempotency_key,
        "provider_id": delivery.provider_id,
        "adapter_version": delivery.adapter_version,
        "environment": delivery.environment,
        "channel": delivery.channel,
        "operation": delivery.operation,
        "correlation_sha256": delivery.correlation_sha256,
        "transport_status": delivery.transport_status,
        "provider_request_id": delivery.provider_request_id,
        "media_type": delivery.media_type,
        "received_at": delivery.received_at,
        "recorded_at": delivery.recorded_at,
        "body": delivery.body,
        "body_size_bytes": delivery.body_size_bytes,
        "body_sha256": delivery.body_sha256,
        "delivery_sha256": delivery.semantic_sha256,
        "canonical_payload": canonical_json_text(_receipt_payload(receipt)),
        "semantic_sha256": receipt.semantic_sha256,
    }


def _required_text(row: BrokerIngressRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise BrokerIngressError(f"persisted broker ingress {field_name} must be a string")
    return value


def _optional_text(row: BrokerIngressRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise BrokerIngressError(f"persisted broker ingress {field_name} must be a string or null")
    return value


def _required_integer(row: BrokerIngressRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise BrokerIngressError(f"persisted broker ingress {field_name} must be an integer")
    return value


def _optional_integer(row: BrokerIngressRow, field_name: str) -> int | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not int:
        raise BrokerIngressError(
            f"persisted broker ingress {field_name} must be an integer or null"
        )
    return value


def _required_datetime(row: BrokerIngressRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise BrokerIngressError(f"persisted broker ingress {field_name} must be a datetime")
    return as_aware_utc(value)


def _required_bytes(row: BrokerIngressRow, field_name: str) -> bytes:
    value = row[field_name]
    if type(value) is bytes:
        return value
    if type(value) is memoryview:
        return value.tobytes()
    raise BrokerIngressError(f"persisted broker ingress {field_name} must be exact bytes")


def broker_ingress_receipt_from_row(row: BrokerIngressRow) -> BrokerIngressReceipt:
    """Strictly decode and authenticate one persisted raw ingress receipt."""

    try:
        delivery = BrokerIngressDelivery(
            account_id=_required_text(row, "account_id"),
            delivery_idempotency_key=_required_text(
                row,
                "delivery_idempotency_key",
            ),
            provider_id=_required_text(row, "provider_id"),
            adapter_version=_required_text(row, "adapter_version"),
            environment=_required_text(row, "environment"),
            channel=_required_text(row, "channel"),
            operation=_required_text(row, "operation"),
            correlation_sha256=_optional_text(row, "correlation_sha256"),
            transport_status=_optional_integer(row, "transport_status"),
            provider_request_id=_optional_text(row, "provider_request_id"),
            media_type=_optional_text(row, "media_type"),
            received_at=_required_datetime(row, "received_at"),
            recorded_at=_required_datetime(row, "recorded_at"),
            body=_required_bytes(row, "body"),
        )
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=_required_integer(row, "ingress_sequence"),
            previous_receipt_sha256=_optional_text(
                row,
                "previous_receipt_sha256",
            ),
        )
        duplicated_values: tuple[tuple[str, object], ...] = (
            ("receipt_id", receipt.receipt_id),
            ("body_size_bytes", delivery.body_size_bytes),
            ("body_sha256", delivery.body_sha256),
            ("delivery_sha256", delivery.semantic_sha256),
            (
                "canonical_payload",
                canonical_json_text(_receipt_payload(receipt)),
            ),
            ("semantic_sha256", receipt.semantic_sha256),
        )
        for field_name, expected in duplicated_values:
            if row[field_name] != expected:
                raise BrokerIngressError(f"persisted broker ingress {field_name} conflicts")
        return receipt
    except BrokerIngressError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerIngressError("persisted broker ingress receipt is malformed") from error


def _head_from_row(row: BrokerIngressRow) -> _BrokerIngressHead:
    try:
        account_id = _require_account_id(_required_text(row, "account_id"))
        last_sequence = _required_integer(row, "last_ingress_sequence")
        last_digest = _optional_text(row, "last_receipt_sha256")
        if last_sequence < 0:
            raise BrokerIngressError("persisted broker ingress head sequence cannot be negative")
        if last_sequence == 0:
            if last_digest is not None:
                raise BrokerIngressError("empty broker ingress head cannot name a terminal receipt")
        else:
            if (
                last_digest is None
                or len(last_digest) != 64
                or any(character not in "0123456789abcdef" for character in last_digest)
            ):
                raise BrokerIngressError(
                    "non-empty broker ingress head requires a terminal receipt digest"
                )
        return _BrokerIngressHead(
            account_id=account_id,
            last_ingress_sequence=last_sequence,
            last_receipt_sha256=last_digest,
        )
    except BrokerIngressError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerIngressError("persisted broker ingress head is malformed") from error


def _head(
    connection: Connection,
    account_id: str,
) -> _BrokerIngressHead | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_ingress_heads).where(
                phase4_broker_ingress_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _insert_empty_head(
    connection: Connection,
    account_id: str,
) -> _BrokerIngressHead:
    try:
        connection.execute(
            sa.insert(phase4_broker_ingress_heads).values(
                account_id=account_id,
                last_ingress_sequence=0,
                last_receipt_sha256=None,
            )
        )
    except IntegrityError as error:
        raise BrokerIngressConflict("broker ingress head conflicts with durable history") from error
    persisted = _head(connection, account_id)
    if persisted != _BrokerIngressHead(account_id, 0, None):
        raise BrokerIngressError("broker ingress head failed exact SQL readback")
    return persisted


def _receipt_by_id(
    connection: Connection,
    receipt_id: str,
) -> BrokerIngressReceipt | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.receipt_id == receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_ingress_receipt_from_row(row)


def _terminal_receipt(
    connection: Connection,
    head: _BrokerIngressHead,
) -> BrokerIngressReceipt | None:
    if head.last_ingress_sequence == 0:
        return None
    assert head.last_receipt_sha256 is not None
    row = (
        connection.execute(
            sa.select(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.account_id == head.account_id,
                phase4_broker_ingress_receipts.c.semantic_sha256 == head.last_receipt_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise BrokerIngressError("broker ingress head references a missing terminal receipt")
    receipt = broker_ingress_receipt_from_row(row)
    if (
        receipt.account_id != head.account_id
        or receipt.ingress_sequence != head.last_ingress_sequence
        or receipt.semantic_sha256 != head.last_receipt_sha256
    ):
        raise BrokerIngressError("broker ingress head conflicts with its terminal receipt")
    return receipt


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[BrokerIngressReceipt, ...]:
    rows = connection.execute(
        sa.select(phase4_broker_ingress_receipts)
        .where(phase4_broker_ingress_receipts.c.account_id == account_id)
        .order_by(phase4_broker_ingress_receipts.c.ingress_sequence)
    ).mappings()
    receipts: list[BrokerIngressReceipt] = []
    previous_digest: str | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        receipt = broker_ingress_receipt_from_row(row)
        _validate_history_receipt(
            account_id=account_id,
            expected_sequence=expected_sequence,
            previous_digest=previous_digest,
            receipt=receipt,
        )
        receipts.append(receipt)
        previous_digest = receipt.semantic_sha256
    return tuple(receipts)


def _validate_history_receipt(
    *,
    account_id: str,
    expected_sequence: int,
    previous_digest: str | None,
    receipt: BrokerIngressReceipt,
) -> None:
    if receipt.account_id != account_id:
        raise BrokerIngressError("broker ingress history contains a receipt for another account")
    if receipt.ingress_sequence != expected_sequence:
        raise BrokerIngressError(
            "broker ingress history is not a contiguous account-local sequence"
        )
    if receipt.previous_receipt_sha256 != previous_digest:
        raise BrokerIngressError("broker ingress history predecessor chain conflicts")


def _verify_streamed_history(
    connection: Connection,
    head: _BrokerIngressHead,
) -> None:
    """Authenticate one journal while retaining at most one raw body at a time."""

    rows = connection.execute(
        sa.select(phase4_broker_ingress_receipts)
        .where(phase4_broker_ingress_receipts.c.account_id == head.account_id)
        .order_by(phase4_broker_ingress_receipts.c.ingress_sequence)
        .execution_options(yield_per=1)
    ).mappings()
    previous_digest: str | None = None
    count = 0
    for count, row in enumerate(rows, start=1):
        receipt = broker_ingress_receipt_from_row(row)
        _validate_history_receipt(
            account_id=head.account_id,
            expected_sequence=count,
            previous_digest=previous_digest,
            receipt=receipt,
        )
        previous_digest = receipt.semantic_sha256
    if count != head.last_ingress_sequence:
        raise BrokerIngressError("broker ingress head sequence conflicts with durable history")
    if previous_digest != head.last_receipt_sha256:
        raise BrokerIngressError(
            "broker ingress head terminal digest conflicts with durable history"
        )


def _require_account_id(account_id: object) -> str:
    if (
        type(account_id) is not str
        or not account_id
        or account_id != account_id.strip()
        or len(account_id) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in account_id)
    ):
        raise BrokerIngressError("broker ingress account ID must be bounded, trimmed text")
    return account_id


def _verified_history(
    connection: Connection,
    account_id: str,
) -> tuple[BrokerIngressReceipt, ...]:
    receipts = _history(connection, account_id)
    head = _head(connection, account_id)
    if head is None:
        if receipts:
            raise BrokerIngressError("broker ingress receipts exist without a durable account head")
        return ()
    if len(receipts) != head.last_ingress_sequence:
        raise BrokerIngressError("broker ingress head sequence conflicts with durable history")
    terminal = None if not receipts else receipts[-1].semantic_sha256
    if terminal != head.last_receipt_sha256:
        raise BrokerIngressError(
            "broker ingress head terminal digest conflicts with durable history"
        )
    _terminal_receipt(connection, head)
    return receipts


def _verify_broker_ingress_integrity(connection: Connection) -> None:
    """Authenticate every raw chain inside a caller-owned stable transaction."""

    receipt_without_head = connection.scalar(
        sa.select(phase4_broker_ingress_receipts.c.account_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_broker_ingress_heads.c.account_id
                    == phase4_broker_ingress_receipts.c.account_id
                )
            )
        )
        .limit(1)
    )
    if receipt_without_head is not None:
        raise BrokerIngressError("broker ingress receipts exist without durable account heads")
    head_rows = (
        connection.execute(
            sa.select(phase4_broker_ingress_heads).order_by(
                phase4_broker_ingress_heads.c.account_id
            )
        )
        .mappings()
        .all()
    )
    for row in head_rows:
        _verify_streamed_history(connection, _head_from_row(row))


def verify_broker_ingress_integrity(engine: Engine) -> None:
    """Authenticate every raw ingress chain in one owned repeatable snapshot."""

    if not isinstance(engine, Engine):
        raise BrokerIngressError("broker ingress verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise BrokerIngressError(
            f"broker ingress verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_broker_ingress_integrity(connection)


class SqlBrokerIngressRepository:
    """Append raw broker deliveries under the durable account transition lock."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise BrokerIngressError("SQL broker ingress requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise BrokerIngressError(
                f"SQL broker ingress does not support dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        """Commit exact bytes before any caller attempts provider decoding."""

        if type(delivery) is not BrokerIngressDelivery:
            raise BrokerIngressError(
                "broker ingress recording requires an exact BrokerIngressDelivery"
            )
        delivery.__post_init__()
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, delivery.account_id)
                head = _head(connection, delivery.account_id)
                if head is None:
                    head = _insert_empty_head(connection, delivery.account_id)
                _terminal_receipt(connection, head)
                existing = _receipt_by_id(connection, delivery.receipt_id)
                if existing is not None:
                    if (
                        existing.account_id != head.account_id
                        or existing.ingress_sequence > head.last_ingress_sequence
                    ):
                        raise BrokerIngressError(
                            "broker ingress receipt exists outside its durable head"
                        )
                    if existing.delivery != delivery:
                        raise BrokerIngressConflict(
                            "broker ingress delivery identity conflicts with durable content"
                        )
                    return existing

                receipt = BrokerIngressReceipt(
                    delivery=delivery,
                    ingress_sequence=head.last_ingress_sequence + 1,
                    previous_receipt_sha256=head.last_receipt_sha256,
                )
                values = immutable_broker_ingress_values(receipt)
                try:
                    connection.execute(sa.insert(phase4_broker_ingress_receipts).values(**values))
                except IntegrityError as error:
                    raise BrokerIngressConflict(
                        "broker ingress receipt conflicts with durable history"
                    ) from error
                prior_digest_predicate = (
                    phase4_broker_ingress_heads.c.last_receipt_sha256.is_(None)
                    if head.last_receipt_sha256 is None
                    else phase4_broker_ingress_heads.c.last_receipt_sha256
                    == head.last_receipt_sha256
                )
                try:
                    updated = connection.execute(
                        sa.update(phase4_broker_ingress_heads)
                        .where(
                            phase4_broker_ingress_heads.c.account_id == delivery.account_id,
                            phase4_broker_ingress_heads.c.last_ingress_sequence
                            == head.last_ingress_sequence,
                            prior_digest_predicate,
                        )
                        .values(
                            last_ingress_sequence=receipt.ingress_sequence,
                            last_receipt_sha256=receipt.semantic_sha256,
                        )
                    )
                except IntegrityError as error:
                    raise BrokerIngressConflict(
                        "broker ingress head update conflicts with durable history"
                    ) from error
                if updated.rowcount != 1:
                    raise BrokerIngressConflict(
                        "broker ingress head changed during sequence allocation"
                    )
                row = (
                    connection.execute(
                        sa.select(phase4_broker_ingress_receipts).where(
                            phase4_broker_ingress_receipts.c.receipt_id == receipt.receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = broker_ingress_receipt_from_row(row)
                if persisted != receipt:
                    raise BrokerIngressError("broker ingress receipt failed exact SQL readback")
                assert_immutable(
                    phase4_broker_ingress_receipts,
                    receipt.receipt_id,
                    row,
                    values,
                )
                persisted_head = _head(connection, delivery.account_id)
                if (
                    persisted_head is None
                    or persisted_head.last_ingress_sequence != receipt.ingress_sequence
                    or persisted_head.last_receipt_sha256 != receipt.semantic_sha256
                ):
                    raise BrokerIngressError("broker ingress head failed exact SQL readback")
                if _terminal_receipt(connection, persisted_head) != receipt:
                    raise BrokerIngressError(
                        "broker ingress terminal receipt failed exact SQL readback"
                    )
                return persisted
        except BrokerIngressError:
            raise
        except AccountCoordinatorError as error:
            raise BrokerIngressError(str(error)) from error

    def load(self, receipt_id: str) -> BrokerIngressReceipt | None:
        """Load one authenticated receipt, or return ``None`` when absent."""

        if (
            type(receipt_id) is not str
            or len(receipt_id) != 64
            or any(character not in "0123456789abcdef" for character in receipt_id)
        ):
            raise BrokerIngressError("broker ingress receipt ID must be a lowercase SHA-256 digest")
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(phase4_broker_ingress_receipts).where(
                        phase4_broker_ingress_receipts.c.receipt_id == receipt_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            receipt = broker_ingress_receipt_from_row(row)
            head = _head(connection, receipt.account_id)
            if head is None or receipt.ingress_sequence > head.last_ingress_sequence:
                raise BrokerIngressError("broker ingress receipt exists outside its durable head")
            _terminal_receipt(connection, head)
            return receipt

    def history(self, account_id: str) -> tuple[BrokerIngressReceipt, ...]:
        """Return one authenticated account-local ingress chain."""

        account_id = _require_account_id(account_id)
        with _repeatable_read_transaction(self._engine) as connection:
            return _verified_history(connection, account_id)


__all__ = [
    "SqlBrokerIngressRepository",
    "broker_ingress_receipt_from_row",
    "immutable_broker_ingress_values",
    "verify_broker_ingress_integrity",
]
