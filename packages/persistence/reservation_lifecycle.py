"""Durable, fence-bound reservation release and remaining-capacity projections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.backtest.simulated_broker import SimulatedBrokerResult
from packages.backtest.simulation_horizon import SimulationHorizonFact
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.batch_risk import BatchRiskAuthorization, BatchRiskReservation
from packages.domain.canonical import canonical_decimal_text, canonical_persisted_decimal
from packages.domain.decimal_math import exact_decimal_sum
from packages.domain.ledger_reducer import LedgerReductionError, reduce_execution_ledger
from packages.domain.market_batch import MarketWatermark
from packages.domain.models import MarketEvent, require_utc
from packages.domain.order_reducer import (
    ORDER_REDUCER_CONTRACT_VERSION,
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    OrderCancelRequest,
    OrderLifecycleError,
    create_order_submission,
    reduce_order_lifecycle,
)
from packages.domain.replay import ReplayResult
from packages.domain.replay_manifest import ReplayRunManifest
from packages.domain.reservation_lifecycle import (
    RESERVATION_LIFECYCLE_CONTRACT_VERSION,
    ReservationCapacityProjection,
    ReservationCapacityState,
    ReservationLifecycleError,
    ReservationReleaseConflict,
    ReservationReleaseFact,
    ReservationReleaseReason,
    project_reservation_capacity,
    record_approval_expired_unsent_release,
    record_broker_rejected_release,
    record_execution_accounted_release,
    record_simulation_horizon_final_release,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.batch_risk import load_batch_risk_decision
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    insert_or_verify_atomic,
)
from packages.persistence.phase2_ledger import (
    Phase2LedgerPersistenceError,
    load_phase2_ledger_entry,
    persist_phase2_ledger_entry,
)
from packages.persistence.schema import (
    phase2_batch_reservations,
    phase2_logical_orders,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_submission_attempts,
)
from packages.persistence.simulation_horizon import persist_simulation_horizon_fact
from packages.persistence.submission_attempt import (
    SubmissionAttemptPersistenceError,
    load_submission_attempt,
)

PHASE2_RESERVATION_LIFECYCLE_PERSISTENCE_VERSION = "phase2-durable-reservation-lifecycle-v1"


class ReservationLifecyclePersistenceError(ReservationReleaseConflict):
    """Durable reservation lifecycle rows are missing, corrupt, or conflicting."""


class ReservationLifecycleFrozen(ReservationLifecyclePersistenceError):
    """A parent reservation is frozen by an unresolved or unsafe effect."""


class SqlAccountFenceValidator(Protocol):
    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


@dataclass(frozen=True, slots=True)
class SqlReservationLifecycleSnapshot:
    projection: ReservationCapacityProjection
    persisted_state: ReservationCapacityState
    state_version: int
    correction_frozen: bool


@dataclass(frozen=True, slots=True)
class SqlReservationReleaseResult:
    fact: ReservationReleaseFact
    snapshot: SqlReservationLifecycleSnapshot
    inserted: bool


@dataclass(frozen=True, slots=True)
class _LockedLifecycle:
    reservation_row: RowMapping
    reservation: BatchRiskReservation
    authorization: BatchRiskAuthorization
    attempts: tuple[CanonicalSubmissionAttempt, ...]
    unknown_authorization_ids: frozenset[str]
    history: tuple[ReservationReleaseFact, ...]
    snapshot: SqlReservationLifecycleSnapshot


def _require_text(value: object, field_name: str, *, maximum: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} must be supported non-empty trimmed text"
        )
    return value


def _require_optional_text(
    value: object,
    field_name: str,
    *,
    maximum: int = 256,
) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name, maximum=maximum)


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} must be a lowercase SHA-256 digest"
        )
    return digest


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_int(value: object, field_name: str, *, allow_zero: bool = False) -> int:
    if type(value) is not int or value < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} must be a {qualifier} integer"
        )
    return value


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise ReservationLifecyclePersistenceError(f"persisted {field_name} must be a datetime")
    result = as_aware_utc(value)
    try:
        require_utc(result, f"persisted {field_name}")
    except ValueError as error:
        raise ReservationLifecyclePersistenceError(str(error)) from error
    return result


def _require_input_datetime(value: datetime, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise ReservationLifecycleError(f"{field_name} must be a datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise ReservationLifecycleError(str(error)) from error
    return value


def _require_decimal(
    value: object,
    field_name: str,
    *,
    whole: bool = False,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} must be a finite non-negative Decimal"
        )
    if whole and value != value.to_integral_value():
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} must be a whole number of shares"
        )
    try:
        return canonical_persisted_decimal(value, f"persisted {field_name}")
    except ValueError as error:
        raise ReservationLifecyclePersistenceError(str(error)) from error


def _require_optional_decimal(
    value: object,
    field_name: str,
    *,
    whole: bool = False,
) -> Decimal | None:
    if value is None:
        return None
    return _require_decimal(value, field_name, whole=whole)


def _datetime_text(value: datetime) -> str:
    require_utc(value, "canonical datetime")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _decode_datetime_text(value: object, field_name: str) -> datetime:
    raw = _require_text(value, field_name)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        ) from error
    if parsed.tzinfo is None:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    result = parsed.astimezone(UTC)
    if raw != _datetime_text(result):
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    return result


def _decode_decimal_text(value: object, field_name: str) -> Decimal:
    raw = _require_text(value, field_name)
    try:
        result = canonical_persisted_decimal(Decimal(raw), f"persisted {field_name}")
    except (InvalidOperation, ValueError) as error:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} is not an exact database Decimal"
        ) from error
    if raw != canonical_decimal_text(result):
        raise ReservationLifecyclePersistenceError(f"persisted {field_name} is not canonical")
    return result


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReservationLifecyclePersistenceError(
                "persisted lifecycle JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_canonical_json(raw: object, field_name: str) -> object:
    if type(raw) is not str:
        raise ReservationLifecyclePersistenceError(f"persisted {field_name} must be JSON text")
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object_pairs)
    except ReservationLifecyclePersistenceError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} is invalid JSON"
        ) from error
    if raw != _json_text(value):
        raise ReservationLifecyclePersistenceError(f"persisted {field_name} is not canonical JSON")
    return value


def _require_object(
    value: object,
    field_name: str,
    expected_keys: frozenset[str],
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected_keys:
        raise ReservationLifecyclePersistenceError(
            f"persisted {field_name} has an invalid object shape"
        )
    return cast(dict[str, Any], value)


def _select_for_update(statement: Any, connection: Connection) -> Any:
    return statement.with_for_update() if connection.dialect.name == "postgresql" else statement


_RELEASE_PAYLOAD_KEYS = frozenset(
    {
        "accounted_quantity",
        "attempt_sha256",
        "authorization_sha256",
        "contract_version",
        "execution_head_quantity",
        "execution_id",
        "execution_revision",
        "order_event_sha256",
        "order_state_sha256",
        "parent_decision_id",
        "persistence_version",
        "previous_release_sha256",
        "reservation_sha256",
        "semantic_sha256",
        "sequence_number",
    }
)


def _release_payload_object(fact: ReservationReleaseFact) -> dict[str, object]:
    return {
        "accounted_quantity": (
            None
            if fact.accounted_quantity is None
            else canonical_decimal_text(fact.accounted_quantity)
        ),
        "attempt_sha256": fact.attempt_sha256,
        "authorization_sha256": fact.authorization_sha256,
        "contract_version": RESERVATION_LIFECYCLE_CONTRACT_VERSION,
        "execution_head_quantity": (
            None
            if fact.execution_head_quantity is None
            else canonical_decimal_text(fact.execution_head_quantity)
        ),
        "execution_id": fact.execution_id,
        "execution_revision": fact.execution_revision,
        "order_event_sha256": fact.order_event_sha256,
        "order_state_sha256": fact.order_state_sha256,
        "parent_decision_id": fact.parent_decision_id,
        "persistence_version": PHASE2_RESERVATION_LIFECYCLE_PERSISTENCE_VERSION,
        "previous_release_sha256": fact.previous_release_sha256,
        "reservation_sha256": fact.reservation_sha256,
        "semantic_sha256": fact.semantic_sha256,
        "sequence_number": fact.sequence_number,
    }


def _release_payload(fact: ReservationReleaseFact) -> str:
    return _json_text(_release_payload_object(fact))


def immutable_reservation_release_values(
    fact: ReservationReleaseFact,
) -> dict[str, object]:
    """Return the complete SQL row for one proof-constructed release fact."""

    if type(fact) is not ReservationReleaseFact:
        raise ReservationLifecyclePersistenceError(
            "release persistence requires an exact ReservationReleaseFact"
        )
    fact._validate()
    return {
        "release_event_id": fact.release_event_id,
        "reservation_id": fact.reservation_id,
        "authorization_id": fact.authorization_id,
        "order_id": fact.order_id,
        "attempt_id": fact.attempt_id,
        "order_event_id": fact.order_event_id,
        "reason": fact.reason.value,
        "finality_reference": fact.finality_reference,
        "source_sha256": fact.source_sha256,
        "released_cash": fact.released_cash,
        "released_buy_exposure": fact.released_buy_exposure,
        "released_sell_quantity": fact.released_sell_quantity,
        "occurred_at": fact.occurred_at,
        "recorded_at": fact.recorded_at,
        "canonical_payload": _release_payload(fact),
        "semantic_sha256": fact.semantic_sha256,
    }


def reservation_release_from_row(row: RowMapping) -> ReservationReleaseFact:
    """Strictly decode and authenticate one persisted release row."""

    payload = _require_object(
        _decode_canonical_json(row["canonical_payload"], "release canonical payload"),
        "release canonical payload",
        _RELEASE_PAYLOAD_KEYS,
    )
    if payload["persistence_version"] != PHASE2_RESERVATION_LIFECYCLE_PERSISTENCE_VERSION:
        raise ReservationLifecyclePersistenceError(
            "persisted release uses an unsupported persistence contract"
        )
    if payload["contract_version"] != RESERVATION_LIFECYCLE_CONTRACT_VERSION:
        raise ReservationLifecyclePersistenceError(
            "persisted release uses an unsupported domain contract"
        )
    try:
        fact = object.__new__(ReservationReleaseFact)
        values: tuple[tuple[str, object], ...] = (
            (
                "release_event_id",
                _require_text(row["release_event_id"], "release event ID", maximum=64),
            ),
            (
                "sequence_number",
                _require_int(payload["sequence_number"], "release sequence number"),
            ),
            (
                "previous_release_sha256",
                _require_optional_sha256(
                    payload["previous_release_sha256"],
                    "previous release digest",
                ),
            ),
            (
                "reservation_id",
                _require_text(row["reservation_id"], "release reservation ID", maximum=64),
            ),
            (
                "reservation_sha256",
                _require_sha256(payload["reservation_sha256"], "reservation digest"),
            ),
            (
                "parent_decision_id",
                _require_text(
                    payload["parent_decision_id"],
                    "release parent decision ID",
                    maximum=64,
                ),
            ),
            (
                "authorization_id",
                _require_text(
                    row["authorization_id"],
                    "release authorization ID",
                    maximum=64,
                ),
            ),
            (
                "authorization_sha256",
                _require_sha256(payload["authorization_sha256"], "authorization digest"),
            ),
            ("order_id", _require_optional_text(row["order_id"], "release order ID")),
            (
                "attempt_id",
                _require_optional_text(row["attempt_id"], "release attempt ID"),
            ),
            (
                "order_event_id",
                _require_optional_text(
                    row["order_event_id"],
                    "release order event ID",
                    maximum=128,
                ),
            ),
            (
                "reason",
                ReservationReleaseReason(
                    _require_text(row["reason"], "release reason", maximum=32)
                ),
            ),
            (
                "finality_reference",
                _require_text(
                    row["finality_reference"],
                    "release finality reference",
                ),
            ),
            ("source_sha256", _require_sha256(row["source_sha256"], "release source")),
            (
                "attempt_sha256",
                _require_optional_sha256(payload["attempt_sha256"], "attempt digest"),
            ),
            (
                "order_state_sha256",
                _require_optional_sha256(
                    payload["order_state_sha256"],
                    "order-state digest",
                ),
            ),
            (
                "order_event_sha256",
                _require_optional_sha256(
                    payload["order_event_sha256"],
                    "order-event digest",
                ),
            ),
            (
                "execution_id",
                _require_optional_text(
                    payload["execution_id"],
                    "release execution ID",
                    maximum=128,
                ),
            ),
            (
                "execution_revision",
                (
                    None
                    if payload["execution_revision"] is None
                    else _require_int(payload["execution_revision"], "execution revision")
                ),
            ),
            (
                "execution_head_quantity",
                (
                    None
                    if payload["execution_head_quantity"] is None
                    else _decode_decimal_text(
                        payload["execution_head_quantity"],
                        "execution head quantity",
                    )
                ),
            ),
            (
                "accounted_quantity",
                (
                    None
                    if payload["accounted_quantity"] is None
                    else _decode_decimal_text(
                        payload["accounted_quantity"],
                        "accounted quantity",
                    )
                ),
            ),
            ("released_cash", _require_decimal(row["released_cash"], "released cash")),
            (
                "released_buy_exposure",
                _require_decimal(
                    row["released_buy_exposure"],
                    "released buy exposure",
                ),
            ),
            (
                "released_sell_quantity",
                _require_decimal(
                    row["released_sell_quantity"],
                    "released sell quantity",
                    whole=True,
                ),
            ),
            ("occurred_at", _require_datetime(row["occurred_at"], "release occurred_at")),
            ("recorded_at", _require_datetime(row["recorded_at"], "release recorded_at")),
        )
        for field_name, value in values:
            object.__setattr__(fact, field_name, value)
        fact._validate()
    except ReservationLifecyclePersistenceError:
        raise
    except (ReservationLifecycleError, KeyError, TypeError, ValueError) as error:
        raise ReservationLifecyclePersistenceError(
            "persisted reservation release is malformed"
        ) from error
    if payload["semantic_sha256"] != fact.semantic_sha256:
        raise ReservationLifecyclePersistenceError(
            "persisted release payload semantic digest conflicts"
        )
    if row["semantic_sha256"] != fact.semantic_sha256 or row[
        "canonical_payload"
    ] != _release_payload(fact):
        raise ReservationLifecyclePersistenceError(
            "persisted release row digest or canonical payload conflicts"
        )
    return fact


_ORDER_EVENT_PAYLOAD_KEYS = frozenset(
    {
        "cancel_request",
        "contract_version",
        "persistence_version",
        "semantic_sha256",
    }
)
_CANCEL_PAYLOAD_KEYS = frozenset(
    {
        "cancel_request_id",
        "order_id",
        "prior_order_state_sha256",
        "reason",
        "requested_at",
    }
)


def _cancel_payload(cancel_request: OrderCancelRequest | None) -> dict[str, object] | None:
    if cancel_request is None:
        return None
    return {
        "cancel_request_id": cancel_request.cancel_request_id,
        "order_id": cancel_request.order_id,
        "prior_order_state_sha256": cancel_request.prior_order_state_sha256,
        "reason": cancel_request.reason,
        "requested_at": _datetime_text(cancel_request.requested_at),
    }


def _order_event_payload(
    event: BrokerOrderEvent,
    cancel_request: OrderCancelRequest | None,
) -> str:
    return _json_text(
        {
            "cancel_request": _cancel_payload(cancel_request),
            "contract_version": ORDER_REDUCER_CONTRACT_VERSION,
            "persistence_version": PHASE2_RESERVATION_LIFECYCLE_PERSISTENCE_VERSION,
            "semantic_sha256": event.semantic_sha256,
        }
    )


def immutable_order_event_values(
    event: BrokerOrderEvent,
    *,
    cancel_request: OrderCancelRequest | None = None,
) -> dict[str, object]:
    """Return an authenticated order-event row, retaining exact cancel evidence."""

    if type(event) is not BrokerOrderEvent:
        raise ReservationLifecyclePersistenceError(
            "order-event persistence requires an exact BrokerOrderEvent"
        )
    try:
        event.__post_init__()
    except (TypeError, ValueError) as error:
        raise ReservationLifecyclePersistenceError("order event is malformed") from error
    if event.kind is BrokerOrderEventKind.CANCELED:
        if type(cancel_request) is not OrderCancelRequest:
            raise ReservationLifecyclePersistenceError(
                "canceled broker event requires exact local cancel evidence"
            )
        cancel_request.__post_init__()
        if cancel_request.order_id != event.order_id:
            raise ReservationLifecyclePersistenceError(
                "cancel request belongs to another logical order"
            )
    elif cancel_request is not None:
        raise ReservationLifecyclePersistenceError(
            "only a canceled broker event may retain cancel-request evidence"
        )
    return {
        "event_id": event.event_id,
        "order_id": event.order_id,
        "broker_order_id": event.broker_order_id,
        "broker_sequence": event.broker_sequence,
        "occurred_at": event.occurred_at,
        "received_at": event.received_at,
        "kind": event.kind.value,
        "reason": event.reason,
        "execution_id": event.execution_id,
        "execution_revision": event.execution_revision,
        "supersedes_event_id": event.supersedes_event_id,
        "quantity": event.quantity,
        "price": event.price,
        "fee": event.fee,
        "canonical_payload": _order_event_payload(event, cancel_request),
        "semantic_sha256": event.semantic_sha256,
    }


def _order_event_from_row(
    row: RowMapping,
) -> tuple[BrokerOrderEvent, OrderCancelRequest | None]:
    payload = _require_object(
        _decode_canonical_json(row["canonical_payload"], "order-event canonical payload"),
        "order-event canonical payload",
        _ORDER_EVENT_PAYLOAD_KEYS,
    )
    if payload["persistence_version"] != PHASE2_RESERVATION_LIFECYCLE_PERSISTENCE_VERSION:
        raise ReservationLifecyclePersistenceError(
            "persisted order event uses an unsupported persistence contract"
        )
    if payload["contract_version"] != ORDER_REDUCER_CONTRACT_VERSION:
        raise ReservationLifecyclePersistenceError(
            "persisted order event uses an unsupported domain contract"
        )
    try:
        event = BrokerOrderEvent(
            event_id=_require_text(row["event_id"], "order event ID", maximum=128),
            order_id=_require_text(row["order_id"], "order ID", maximum=64),
            broker_order_id=_require_text(
                row["broker_order_id"],
                "broker order ID",
                maximum=128,
            ),
            broker_sequence=_require_int(row["broker_sequence"], "broker sequence"),
            occurred_at=_require_datetime(row["occurred_at"], "order event occurred_at"),
            received_at=_require_datetime(row["received_at"], "order event received_at"),
            kind=BrokerOrderEventKind(_require_text(row["kind"], "order event kind", maximum=32)),
            reason=_require_optional_text(row["reason"], "order event reason", maximum=512),
            execution_id=_require_optional_text(
                row["execution_id"],
                "execution ID",
                maximum=128,
            ),
            execution_revision=(
                None
                if row["execution_revision"] is None
                else _require_int(row["execution_revision"], "execution revision")
            ),
            supersedes_event_id=_require_optional_text(
                row["supersedes_event_id"],
                "superseded event ID",
                maximum=128,
            ),
            quantity=_require_optional_decimal(
                row["quantity"],
                "execution quantity",
                whole=True,
            ),
            price=_require_optional_decimal(row["price"], "execution price"),
            fee=_require_optional_decimal(row["fee"], "execution fee"),
        )
    except ReservationLifecyclePersistenceError:
        raise
    except (OrderLifecycleError, TypeError, ValueError) as error:
        raise ReservationLifecyclePersistenceError(
            "persisted broker order event is malformed"
        ) from error
    cancel_raw = payload["cancel_request"]
    cancel_request: OrderCancelRequest | None = None
    if cancel_raw is not None:
        cancel_payload = _require_object(
            cancel_raw,
            "cancel-request payload",
            _CANCEL_PAYLOAD_KEYS,
        )
        try:
            cancel_request = OrderCancelRequest(
                cancel_request_id=_require_text(
                    cancel_payload["cancel_request_id"],
                    "cancel request ID",
                    maximum=128,
                ),
                order_id=_require_text(
                    cancel_payload["order_id"],
                    "cancel order ID",
                    maximum=64,
                ),
                prior_order_state_sha256=_require_sha256(
                    cancel_payload["prior_order_state_sha256"],
                    "cancel prior-state digest",
                ),
                requested_at=_decode_datetime_text(
                    cancel_payload["requested_at"],
                    "cancel requested_at",
                ),
                reason=_require_text(
                    cancel_payload["reason"],
                    "cancel reason",
                ),
            )
        except ReservationLifecyclePersistenceError:
            raise
        except (OrderLifecycleError, TypeError, ValueError) as error:
            raise ReservationLifecyclePersistenceError(
                "persisted cancel request is malformed"
            ) from error
    expected = immutable_order_event_values(event, cancel_request=cancel_request)
    if payload["semantic_sha256"] != event.semantic_sha256 or any(
        row[field_name] != expected_value
        for field_name, expected_value in expected.items()
        if field_name not in {"quantity", "price", "fee", "occurred_at", "received_at"}
    ):
        raise ReservationLifecyclePersistenceError(
            "persisted order-event identity or payload conflicts"
        )
    for field_name in ("quantity", "price", "fee"):
        expected_value = expected[field_name]
        actual_value = row[field_name]
        if expected_value is None:
            if actual_value is not None:
                raise ReservationLifecyclePersistenceError(
                    "persisted order-event Decimal shape conflicts"
                )
        elif Decimal(str(actual_value)) != expected_value:
            raise ReservationLifecyclePersistenceError(
                "persisted order-event Decimal value conflicts"
            )
    for field_name in ("occurred_at", "received_at"):
        if _require_datetime(row[field_name], field_name) != expected[field_name]:
            raise ReservationLifecyclePersistenceError("persisted order-event time conflicts")
    return event, cancel_request


def _authorization(
    reservation: BatchRiskReservation,
    authorization_id: str,
) -> BatchRiskAuthorization:
    matches = tuple(
        authorization
        for authorization in reservation.authorizations
        if authorization.decision_id == authorization_id
    )
    if len(matches) != 1:
        raise ReservationLifecyclePersistenceError(
            "reservation does not contain the requested exact authorization"
        )
    return matches[0]


def _logical_order_row(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
) -> RowMapping:
    row = (
        connection.execute(
            sa.select(phase2_logical_orders).where(
                phase2_logical_orders.c.order_id == attempt.order_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ReservationLifecyclePersistenceError(
            "submission attempt references a missing logical order"
        )
    return row


def _order_state(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
) -> CanonicalOrderState:
    row = _logical_order_row(connection, attempt)
    if (
        row["authorization_id"] != authorization.decision_id
        or row["reservation_id"] != authorization.reservation_id
        or row["parent_decision_id"] != authorization.parent_decision_id
        or row["intent_id"] != authorization.intent_id
        or row["intent_payload_sha256"] != authorization.intent_payload_hash
    ):
        raise ReservationLifecyclePersistenceError(
            "logical order conflicts with its attempt and authorization"
        )
    initial_submitted_at = _require_datetime(
        row["submitted_at"],
        "logical order initial submitted_at",
    )
    if initial_submitted_at > attempt.preparation.prepared_at:
        raise ReservationLifecyclePersistenceError(
            "logical order initial preparation follows its selected attempt"
        )
    try:
        submission = create_order_submission(
            intent=attempt.preparation.intent,
            risk_decision_id=authorization.decision_id,
            submission_attempt_id=attempt.attempt_id,
            submitted_at=attempt.preparation.prepared_at,
        )
    except (OrderLifecycleError, TypeError, ValueError) as error:
        raise ReservationLifecyclePersistenceError(
            "persisted logical order cannot reconstruct submission evidence"
        ) from error
    if (
        submission.order_id != row["order_id"]
        or submission.client_order_id != row["client_order_id"]
    ):
        raise ReservationLifecyclePersistenceError(
            "logical order changed deterministic submission identity"
        )
    decoded = tuple(
        _order_event_from_row(event_row)
        for event_row in connection.execute(
            sa.select(phase2_order_events)
            .where(phase2_order_events.c.order_id == attempt.order_id)
            .order_by(phase2_order_events.c.broker_sequence)
        )
        .mappings()
        .all()
    )
    events = tuple(item[0] for item in decoded)
    cancel_requests = tuple(item[1] for item in decoded if item[1] is not None)
    if len(cancel_requests) > 1:
        raise ReservationLifecyclePersistenceError(
            "persisted order history contains multiple cancel requests"
        )
    cancel_request = None if not cancel_requests else cancel_requests[0]
    try:
        return reduce_order_lifecycle(
            submission=submission,
            broker_events=events,
            cancel_request=cancel_request,
        )
    except OrderLifecycleError as error:
        raise ReservationLifecyclePersistenceError(
            "persisted order-event history is not canonical"
        ) from error


def load_canonical_order_state(
    connection: Connection,
    attempt_id: str,
) -> CanonicalOrderState | None:
    """Strictly reconstruct the canonical order state for one durable attempt."""

    try:
        attempt = load_submission_attempt(connection, attempt_id)
    except SubmissionAttemptPersistenceError as error:
        raise ReservationLifecyclePersistenceError(
            "persisted submission attempt is malformed"
        ) from error
    if attempt is None:
        return None
    decision = load_batch_risk_decision(connection, attempt.parent_decision_id)
    if decision is None or decision.reservation is None:
        raise ReservationLifecyclePersistenceError(
            "order attempt lacks its complete approved reservation"
        )
    authorization = _authorization(
        decision.reservation,
        attempt.preparation.authorization_id,
    )
    return _order_state(connection, attempt, authorization)


def _persist_order_state(
    connection: Connection,
    supplied: CanonicalOrderState,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
) -> CanonicalOrderState:
    try:
        rebuilt = reduce_order_lifecycle(
            submission=supplied.submission,
            broker_events=supplied.broker_events,
            cancel_request=supplied.cancel_request,
        )
    except OrderLifecycleError as error:
        raise ReservationLifecyclePersistenceError(
            "supplied order state is not canonical"
        ) from error
    if rebuilt != supplied:
        raise ReservationLifecyclePersistenceError("supplied order state is not reducer-produced")
    if (
        supplied.submission.order_id != attempt.order_id
        or supplied.submission.submission_attempt_id != attempt.attempt_id
        or supplied.submission.risk_decision_id != authorization.decision_id
        or supplied.submission.intent != attempt.preparation.intent
    ):
        raise ReservationLifecyclePersistenceError(
            "supplied order state conflicts with durable submission evidence"
        )
    if supplied.cancel_request is not None and not any(
        event.kind is BrokerOrderEventKind.CANCELED for event in supplied.broker_events
    ):
        raise ReservationLifecyclePersistenceError(
            "pending cancel requests lack a durable schema fact and cannot authorize release"
        )
    try:
        for event in supplied.broker_events:
            cancel_request = (
                supplied.cancel_request if event.kind is BrokerOrderEventKind.CANCELED else None
            )
            insert_or_verify_atomic(
                connection,
                phase2_order_events,
                immutable_order_event_values(event, cancel_request=cancel_request),
            )
    except (ImmutableFactConflict, IntegrityError) as error:
        raise ReservationLifecyclePersistenceError(
            "order event conflicts with immutable SQL history"
        ) from error
    persisted = _order_state(connection, attempt, authorization)
    if persisted != supplied:
        raise ReservationLifecyclePersistenceError(
            "supplied order state is not the complete durable order history"
        )
    return persisted


def _release_history(
    connection: Connection,
    reservation: BatchRiskReservation,
) -> tuple[ReservationReleaseFact, ...]:
    facts = tuple(
        reservation_release_from_row(row)
        for row in connection.execute(
            sa.select(phase2_reservation_release_events).where(
                phase2_reservation_release_events.c.reservation_id == reservation.reservation_id
            )
        )
        .mappings()
        .all()
    )
    ordered = tuple(sorted(facts, key=lambda fact: fact.sequence_number))
    project_reservation_capacity(reservation, ordered)
    return ordered


def load_reservation_release_history(
    connection: Connection,
    reservation_id: str,
) -> tuple[ReservationReleaseFact, ...]:
    """Strictly load one release chain after authenticating its parent reservation."""

    row = (
        connection.execute(
            sa.select(phase2_batch_reservations).where(
                phase2_batch_reservations.c.reservation_id == reservation_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return ()
    decision = load_batch_risk_decision(connection, str(row["parent_decision_id"]))
    if decision is None or decision.reservation is None:
        raise ReservationLifecyclePersistenceError(
            "release history lacks its complete approved reservation"
        )
    return _release_history(connection, decision.reservation)


def _parent_attempts(
    connection: Connection,
    parent_decision_id: str,
    *,
    lock: bool,
) -> tuple[CanonicalSubmissionAttempt, ...]:
    statement = (
        sa.select(phase2_submission_attempts.c.attempt_id)
        .where(phase2_submission_attempts.c.parent_decision_id == parent_decision_id)
        .order_by(
            phase2_submission_attempts.c.order_id,
            phase2_submission_attempts.c.attempt_number,
            phase2_submission_attempts.c.attempt_id,
        )
    )
    rows = tuple(
        connection.execute(_select_for_update(statement, connection) if lock else statement).all()
    )
    attempts: list[CanonicalSubmissionAttempt] = []
    for row in rows:
        attempt = load_submission_attempt(connection, str(row[0]))
        if attempt is None:  # pragma: no cover - selected immediately above
            raise ReservationLifecyclePersistenceError(
                "submission attempt disappeared during lifecycle reduction"
            )
        attempts.append(attempt)
    return tuple(attempts)


def _unknown_authorization_ids(
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> frozenset[str]:
    return frozenset(
        attempt.preparation.authorization_id
        for attempt in attempts
        if attempt.state is SubmissionAttemptState.UNKNOWN
    )


def _persisted_state(row: RowMapping) -> ReservationCapacityState:
    try:
        return ReservationCapacityState(
            _require_text(row["state"], "reservation state", maximum=24)
        )
    except ValueError as error:
        raise ReservationLifecyclePersistenceError(
            "persisted reservation state is unsupported"
        ) from error


def _snapshot_from_head(
    row: RowMapping,
    projection: ReservationCapacityProjection,
    unknown_authorization_ids: frozenset[str],
) -> SqlReservationLifecycleSnapshot:
    state = _persisted_state(row)
    state_version = _require_int(row["state_version"], "reservation state version")
    remaining_count = _require_int(
        row["remaining_authorization_count"],
        "remaining authorization count",
        allow_zero=True,
    )
    remaining_cash = _require_decimal(row["remaining_cash"], "remaining cash")
    remaining_exposure = _require_decimal(
        row["remaining_buy_exposure"],
        "remaining buy exposure",
    )
    released_at_raw = row["released_at"]
    released_at = (
        None
        if released_at_raw is None
        else _require_datetime(released_at_raw, "reservation released_at")
    )
    if (
        remaining_count != projection.remaining_authorization_count
        or remaining_cash != projection.remaining_cash
        or remaining_exposure != projection.remaining_buy_exposure
        or released_at != projection.released_at
    ):
        raise ReservationLifecyclePersistenceError(
            "reservation head counters disagree with its immutable release history"
        )
    correction_frozen = (
        state is ReservationCapacityState.FROZEN
        and not unknown_authorization_ids
        and projection.state
        in (
            ReservationCapacityState.ACTIVE,
            ReservationCapacityState.PARTIALLY_RELEASED,
        )
    )
    if state is not projection.state and not correction_frozen:
        raise ReservationLifecyclePersistenceError(
            "reservation head state disagrees with release and UNKNOWN evidence"
        )
    if bool(unknown_authorization_ids) != (projection.state is ReservationCapacityState.FROZEN):
        raise ReservationLifecyclePersistenceError(
            "UNKNOWN authorization projection is internally inconsistent"
        )
    return SqlReservationLifecycleSnapshot(
        projection=projection,
        persisted_state=state,
        state_version=state_version,
        correction_frozen=correction_frozen,
    )


def _locked_reservation_row(
    connection: Connection,
    reservation_id: str,
) -> RowMapping:
    row = (
        connection.execute(
            _select_for_update(
                sa.select(phase2_batch_reservations).where(
                    phase2_batch_reservations.c.reservation_id == reservation_id
                ),
                connection,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ReservationLifecyclePersistenceError("reservation does not exist")
    return row


def _lifecycle_from_locked_row(
    connection: Connection,
    row: RowMapping,
    authorization_id: str,
) -> _LockedLifecycle:
    parent_decision_id = _require_text(
        row["parent_decision_id"],
        "reservation parent decision ID",
        maximum=64,
    )
    decision = load_batch_risk_decision(connection, parent_decision_id)
    if decision is None or decision.reservation is None:
        raise ReservationLifecyclePersistenceError(
            "reservation lacks its complete approved parent decision"
        )
    reservation = decision.reservation
    if reservation.reservation_id != row["reservation_id"]:
        raise ReservationLifecyclePersistenceError(
            "loaded risk decision changed reservation identity"
        )
    authorization = _authorization(reservation, authorization_id)
    attempts = _parent_attempts(connection, parent_decision_id, lock=True)
    unknown = _unknown_authorization_ids(attempts)
    history = _release_history(connection, reservation)
    try:
        projection = project_reservation_capacity(
            reservation,
            history,
            unknown_authorization_ids=unknown,
        )
    except ReservationLifecycleError as error:
        raise ReservationLifecyclePersistenceError(
            "release history conflicts with UNKNOWN submission evidence"
        ) from error
    snapshot = _snapshot_from_head(row, projection, unknown)
    return _LockedLifecycle(
        reservation_row=row,
        reservation=reservation,
        authorization=authorization,
        attempts=attempts,
        unknown_authorization_ids=unknown,
        history=history,
        snapshot=snapshot,
    )


_UNSPECIFIED = object()


def _existing_fact(
    lifecycle: _LockedLifecycle,
    *,
    reason: ReservationReleaseReason,
    finality_reference: str,
    source_sha256: str | None | object = _UNSPECIFIED,
    order_id: str | None | object = _UNSPECIFIED,
    attempt_id: str | None | object = _UNSPECIFIED,
    order_event_id: str | None | object = _UNSPECIFIED,
) -> ReservationReleaseFact | None:
    matches = tuple(
        fact
        for fact in lifecycle.history
        if fact.authorization_id == lifecycle.authorization.decision_id
        and fact.reason is reason
        and fact.finality_reference == finality_reference
    )
    if not matches:
        return None
    if len(matches) != 1:
        raise ReservationLifecyclePersistenceError(
            "release finality identity is duplicated in immutable history"
        )
    fact = matches[0]
    expected = (
        (fact.source_sha256, source_sha256, "source digest"),
        (fact.order_id, order_id, "order ID"),
        (fact.attempt_id, attempt_id, "attempt ID"),
        (fact.order_event_id, order_event_id, "order-event ID"),
    )
    for actual, requested, field_name in expected:
        if requested is not _UNSPECIFIED and actual != requested:
            raise ReservationLifecyclePersistenceError(
                f"release retry conflicts in immutable {field_name}"
            )
    return fact


def _require_mutable(
    lifecycle: _LockedLifecycle,
    *,
    allow_correction_frozen: bool = False,
) -> None:
    if lifecycle.unknown_authorization_ids:
        raise ReservationLifecycleFrozen(
            "unresolved UNKNOWN submission freezes the complete parent reservation"
        )
    if lifecycle.snapshot.correction_frozen and not allow_correction_frozen:
        raise ReservationLifecycleFrozen(
            "reservation is frozen by a non-monotone execution correction"
        )
    if lifecycle.snapshot.persisted_state is ReservationCapacityState.RELEASED:
        raise ReservationLifecyclePersistenceError("reservation is already fully released")


def _updated_snapshot(
    connection: Connection,
    lifecycle: _LockedLifecycle,
    projection: ReservationCapacityProjection,
) -> SqlReservationLifecycleSnapshot:
    next_version = lifecycle.snapshot.state_version + 1
    result = connection.execute(
        sa.update(phase2_batch_reservations)
        .where(
            phase2_batch_reservations.c.reservation_id == lifecycle.reservation.reservation_id,
            phase2_batch_reservations.c.state_version == lifecycle.snapshot.state_version,
        )
        .values(
            state=projection.state.value,
            state_version=next_version,
            remaining_authorization_count=projection.remaining_authorization_count,
            remaining_cash=projection.remaining_cash,
            remaining_buy_exposure=projection.remaining_buy_exposure,
            released_at=projection.released_at,
        )
    )
    if result.rowcount != 1:
        raise ReservationLifecyclePersistenceError(
            "reservation head changed concurrently during release"
        )
    row = _locked_reservation_row(connection, lifecycle.reservation.reservation_id)
    return _snapshot_from_head(row, projection, frozenset())


def _insert_release(
    connection: Connection,
    lifecycle: _LockedLifecycle,
    fact: ReservationReleaseFact,
) -> SqlReservationReleaseResult:
    try:
        inserted = insert_or_verify_atomic(
            connection,
            phase2_reservation_release_events,
            immutable_reservation_release_values(fact),
        )
    except (ImmutableFactConflict, IntegrityError) as error:
        raise ReservationLifecyclePersistenceError(
            "release fact conflicts with immutable SQL history"
        ) from error
    if not inserted:
        raise ReservationLifecyclePersistenceError(
            "release fact appeared concurrently despite locked parent"
        )
    history = (*lifecycle.history, fact)
    projection = project_reservation_capacity(lifecycle.reservation, history)
    snapshot = _updated_snapshot(connection, lifecycle, projection)
    persisted_history = _release_history(connection, lifecycle.reservation)
    if persisted_history != history:
        raise ReservationLifecyclePersistenceError(
            "SQL storage did not preserve the exact release chain"
        )
    return SqlReservationReleaseResult(fact=fact, snapshot=snapshot, inserted=True)


def _retry_result(
    lifecycle: _LockedLifecycle,
    fact: ReservationReleaseFact,
) -> SqlReservationReleaseResult:
    return SqlReservationReleaseResult(
        fact=fact,
        snapshot=lifecycle.snapshot,
        inserted=False,
    )


def _require_simulation_execution_coverage(
    connection: Connection,
    *,
    history: tuple[ReservationReleaseFact, ...],
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    account_id: str,
    execution_currency: str,
) -> None:
    try:
        expected_entries = {
            entry.entry_id: entry
            for entry in reduce_execution_ledger(
                order_states=(order_state,),
                execution_currency=execution_currency,
            ).entries
        }
    except LedgerReductionError as error:
        raise ReservationLifecyclePersistenceError(
            "simulation horizon cannot reconstruct canonical execution economics"
        ) from error
    final_execution_ids = {execution.execution_id for execution in order_state.executions}
    relevant = tuple(
        fact
        for fact in history
        if fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
        and fact.authorization_id == authorization.decision_id
        and fact.attempt_id == attempt.attempt_id
        and fact.order_id == order_state.submission.order_id
    )
    if any(fact.execution_id not in final_execution_ids for fact in relevant):
        raise ReservationLifecyclePersistenceError(
            "simulation horizon accounting names an execution absent from final order state"
        )
    events_by_id = {event.event_id: event for event in order_state.broker_events}
    for execution in order_state.executions:
        execution_facts = tuple(
            fact for fact in relevant if fact.execution_id == execution.execution_id
        )
        accounted_quantity = exact_decimal_sum(
            fact.accounted_quantity
            for fact in execution_facts
            if fact.accounted_quantity is not None
        )
        head_event = events_by_id.get(execution.event_id)
        exact_head_facts = tuple(
            fact
            for fact in execution_facts
            if fact.execution_revision == execution.revision
            and fact.execution_head_quantity == execution.quantity
            and fact.order_event_id == execution.event_id
            and head_event is not None
            and fact.order_event_sha256 == head_event.semantic_sha256
        )
        if accounted_quantity != execution.quantity or len(exact_head_facts) != 1:
            raise ReservationLifecyclePersistenceError(
                "simulation horizon requires exact final execution-head accounting coverage"
            )
        for accounting_fact in execution_facts:
            try:
                persisted_entry = load_phase2_ledger_entry(
                    connection,
                    accounting_fact.finality_reference,
                )
            except Phase2LedgerPersistenceError as error:
                raise ReservationLifecyclePersistenceError(
                    "simulation horizon accounting ledger evidence is malformed"
                ) from error
            expected_entry = expected_entries.get(accounting_fact.finality_reference)
            if (
                persisted_entry is None
                or expected_entry is None
                or persisted_entry != (account_id, expected_entry)
                or expected_entry.entry_id != accounting_fact.finality_reference
                or expected_entry.reference_id != accounting_fact.order_event_id
                or expected_entry.source_sha256 != accounting_fact.order_event_sha256
                or expected_entry.semantic_sha256 != accounting_fact.source_sha256
                or expected_entry.effective_at > accounting_fact.occurred_at
                or expected_entry.recorded_at > accounting_fact.occurred_at
            ):
                raise ReservationLifecyclePersistenceError(
                    "simulation horizon accounting lacks exact canonical ledger economics"
                )


def verify_simulation_horizon_release_binding(
    connection: Connection,
    horizon: SimulationHorizonFact,
) -> ReservationReleaseFact:
    """Authenticate one horizon's unique release and exact execution coverage."""

    if type(horizon) is not SimulationHorizonFact:
        raise ReservationLifecyclePersistenceError(
            "horizon release verification requires an exact SimulationHorizonFact"
        )
    history = load_reservation_release_history(connection, horizon.reservation_id)
    matches = tuple(
        fact
        for fact in history
        if fact.reason is ReservationReleaseReason.SIMULATION_HORIZON_FINAL
        and fact.finality_reference == horizon.horizon_reference
    )
    if len(matches) != 1:
        raise ReservationLifecyclePersistenceError(
            "simulation horizon does not have one exact durable release"
        )
    release = matches[0]
    attempt = load_submission_attempt(connection, horizon.attempt_id)
    decision = load_batch_risk_decision(connection, horizon.parent_decision_id)
    order_state = load_canonical_order_state(connection, horizon.attempt_id)
    if attempt is None or decision is None or decision.reservation is None or order_state is None:
        raise ReservationLifecyclePersistenceError(
            "simulation horizon release lacks complete durable execution evidence"
        )
    authorization = _authorization(decision.reservation, horizon.authorization_id)
    final_event = order_state.broker_events[-1] if order_state.broker_events else None
    if final_event is None or (
        release.reservation_id != horizon.reservation_id
        or release.parent_decision_id != horizon.parent_decision_id
        or release.authorization_id != horizon.authorization_id
        or release.attempt_id != horizon.attempt_id
        or release.attempt_sha256 != horizon.attempt_sha256
        or release.order_id != horizon.order_id
        or release.order_state_sha256 != horizon.order_state_sha256
        or release.order_event_id != horizon.final_order_event_id
        or release.order_event_sha256 != horizon.final_order_event_sha256
        or release.source_sha256 != horizon.horizon_source_sha256
        or release.occurred_at != horizon.horizon_at
        or final_event.event_id != horizon.final_order_event_id
        or final_event.semantic_sha256 != horizon.final_order_event_sha256
    ):
        raise ReservationLifecyclePersistenceError(
            "simulation horizon release conflicts with its reconstructed proof"
        )
    _require_simulation_execution_coverage(
        connection,
        history=history,
        authorization=authorization,
        attempt=attempt,
        order_state=order_state,
        account_id=decision.account_id,
        execution_currency=decision.currency,
    )
    return release


class SqlReservationLifecycleRepository:
    """Append finality facts and update one reservation head in a fenced transaction."""

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise ReservationLifecyclePersistenceError(
                "reservation lifecycle repository requires a SQLAlchemy Engine"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise ReservationLifecyclePersistenceError(
                "reservation lifecycle repository requires a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    def get(self, reservation_id: str) -> SqlReservationLifecycleSnapshot | None:
        """Strictly rebuild a reservation projection and authenticate its mutable head."""

        _require_text(reservation_id, "reservation ID", maximum=64)
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(phase2_batch_reservations).where(
                        phase2_batch_reservations.c.reservation_id == reservation_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            decision = load_batch_risk_decision(
                connection,
                _require_text(
                    row["parent_decision_id"],
                    "reservation parent decision ID",
                    maximum=64,
                ),
            )
            if decision is None or decision.reservation is None:
                raise ReservationLifecyclePersistenceError(
                    "reservation lacks its approved parent decision"
                )
            authorization_id = decision.reservation.authorizations[0].decision_id
            return _lifecycle_from_locked_row(
                connection,
                row,
                authorization_id,
            ).snapshot

    def history(self, reservation_id: str) -> tuple[ReservationReleaseFact, ...]:
        with self._engine.connect() as connection:
            return load_reservation_release_history(connection, reservation_id)

    def order_state(self, attempt_id: str) -> CanonicalOrderState | None:
        with self._engine.connect() as connection:
            return load_canonical_order_state(connection, attempt_id)

    def expire_unsent(
        self,
        *,
        reservation_id: str,
        authorization_id: str,
        fence: AccountFence,
        finality_reference: str,
        observed_at: datetime,
        recorded_at: datetime,
    ) -> SqlReservationReleaseResult:
        observed_at = _require_input_datetime(observed_at, "expiry observed_at")
        recorded_at = _require_input_datetime(recorded_at, "expiry recorded_at")
        with _write_transaction(self._engine) as connection:
            lifecycle = self._lock(
                connection,
                reservation_id=reservation_id,
                authorization_id=authorization_id,
                fence=fence,
                checked_at=recorded_at,
            )
            existing = _existing_fact(
                lifecycle,
                reason=ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT,
                finality_reference=finality_reference,
            )
            if existing is not None:
                return _retry_result(lifecycle, existing)
            _require_mutable(lifecycle)
            fact = record_approval_expired_unsent_release(
                reservation=lifecycle.reservation,
                authorization=lifecycle.authorization,
                parent_attempts=lifecycle.attempts,
                finality_reference=finality_reference,
                observed_at=observed_at,
                recorded_at=recorded_at,
                prior_releases=lifecycle.history,
            )
            return _insert_release(connection, lifecycle, fact)

    def broker_rejected(
        self,
        *,
        reservation_id: str,
        authorization_id: str,
        attempt_id: str,
        order_state: CanonicalOrderState,
        rejection_event: BrokerOrderEvent,
        fence: AccountFence,
        recorded_at: datetime,
    ) -> SqlReservationReleaseResult:
        recorded_at = _require_input_datetime(recorded_at, "rejection recorded_at")
        with _write_transaction(self._engine) as connection:
            lifecycle = self._lock(
                connection,
                reservation_id=reservation_id,
                authorization_id=authorization_id,
                fence=fence,
                checked_at=recorded_at,
            )
            attempt = self._attempt(lifecycle, attempt_id)
            persisted_order = _persist_order_state(
                connection,
                order_state,
                attempt,
                lifecycle.authorization,
            )
            existing = _existing_fact(
                lifecycle,
                reason=ReservationReleaseReason.BROKER_REJECTED,
                finality_reference=rejection_event.event_id,
                source_sha256=rejection_event.semantic_sha256,
                order_id=persisted_order.submission.order_id,
                attempt_id=attempt.attempt_id,
                order_event_id=rejection_event.event_id,
            )
            if existing is not None:
                if existing.order_state_sha256 != persisted_order.semantic_sha256:
                    raise ReservationLifecyclePersistenceError(
                        "release retry changed canonical order-state evidence"
                    )
                return _retry_result(lifecycle, existing)
            _require_mutable(lifecycle)
            fact = record_broker_rejected_release(
                reservation=lifecycle.reservation,
                authorization=lifecycle.authorization,
                attempt=attempt,
                order_state=persisted_order,
                rejection_event=rejection_event,
                recorded_at=recorded_at,
                prior_releases=lifecycle.history,
            )
            return _insert_release(connection, lifecycle, fact)

    def execution_accounted(
        self,
        *,
        reservation_id: str,
        authorization_id: str,
        attempt_id: str,
        order_state: CanonicalOrderState,
        execution_event: BrokerOrderEvent,
        accounting_reference: str,
        accounting_source_sha256: str,
        fence: AccountFence,
        accounted_at: datetime,
        recorded_at: datetime,
    ) -> SqlReservationReleaseResult:
        accounted_at = _require_input_datetime(accounted_at, "execution accounted_at")
        recorded_at = _require_input_datetime(recorded_at, "execution release recorded_at")
        frozen_error: ReservationLifecycleFrozen | None = None
        result: SqlReservationReleaseResult | None = None
        with _write_transaction(self._engine) as connection:
            lifecycle = self._lock(
                connection,
                reservation_id=reservation_id,
                authorization_id=authorization_id,
                fence=fence,
                checked_at=recorded_at,
            )
            attempt = self._attempt(lifecycle, attempt_id)
            persisted_order = _persist_order_state(
                connection,
                order_state,
                attempt,
                lifecycle.authorization,
            )
            self._persist_accounting_source(
                connection,
                lifecycle,
                persisted_order,
                execution_event,
                accounting_reference=accounting_reference,
                accounting_source_sha256=accounting_source_sha256,
                accounted_at=accounted_at,
            )
            existing = _existing_fact(
                lifecycle,
                reason=ReservationReleaseReason.EXECUTION_ACCOUNTED,
                finality_reference=accounting_reference,
                source_sha256=accounting_source_sha256,
                order_id=persisted_order.submission.order_id,
                attempt_id=attempt.attempt_id,
                order_event_id=execution_event.event_id,
            )
            if existing is not None:
                if existing.order_state_sha256 != persisted_order.semantic_sha256:
                    raise ReservationLifecyclePersistenceError(
                        "execution retry changed canonical order-state evidence"
                    )
                result = _retry_result(lifecycle, existing)
            else:
                _require_mutable(lifecycle)
                assert execution_event.execution_id is not None
                assert execution_event.quantity is not None
                prior_accounted = exact_decimal_sum(
                    fact.accounted_quantity
                    for fact in lifecycle.history
                    if fact.authorization_id == lifecycle.authorization.decision_id
                    and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
                    and fact.execution_id == execution_event.execution_id
                    and fact.accounted_quantity is not None
                )
                if execution_event.quantity <= prior_accounted:
                    self._freeze_for_correction(connection, lifecycle)
                    frozen_error = ReservationLifecycleFrozen(
                        "downward or non-monotone execution correction froze the reservation"
                    )
                else:
                    fact = record_execution_accounted_release(
                        reservation=lifecycle.reservation,
                        authorization=lifecycle.authorization,
                        attempt=attempt,
                        order_state=persisted_order,
                        execution_event=execution_event,
                        accounting_reference=accounting_reference,
                        accounting_source_sha256=accounting_source_sha256,
                        accounted_at=accounted_at,
                        recorded_at=recorded_at,
                        prior_releases=lifecycle.history,
                    )
                    result = _insert_release(connection, lifecycle, fact)
        if frozen_error is not None:
            raise frozen_error
        if result is None:  # pragma: no cover - every branch above sets a terminal result
            raise ReservationLifecyclePersistenceError(
                "execution release transaction produced no result"
            )
        return result

    def reconciled_terminal(
        self,
        *,
        reservation_id: str,
        authorization_id: str,
        attempt_id: str,
        order_state: CanonicalOrderState | None,
        terminal_event: BrokerOrderEvent | None,
        reconciliation_reference: str,
        reconciliation_source_sha256: str,
        fence: AccountFence,
        reconciled_at: datetime,
        recorded_at: datetime,
    ) -> SqlReservationReleaseResult:
        del (
            reservation_id,
            authorization_id,
            attempt_id,
            order_state,
            terminal_event,
            reconciliation_reference,
            reconciliation_source_sha256,
            fence,
            reconciled_at,
            recorded_at,
        )
        raise ReservationLifecyclePersistenceError(
            "sent-order terminal release requires a durable external reconciliation "
            "evidence producer"
        )

    def simulation_horizon_final(
        self,
        *,
        result: SimulatedBrokerResult,
        replay: ReplayResult,
        replay_events: tuple[MarketEvent, ...],
        replay_watermarks: tuple[MarketWatermark, ...],
        replay_manifest: ReplayRunManifest,
        fence: AccountFence,
        recorded_at: datetime,
    ) -> SqlReservationReleaseResult:
        if type(result) is not SimulatedBrokerResult:
            raise ReservationLifecyclePersistenceError(
                "simulation-horizon release requires an exact simulated broker result"
            )
        recorded_at = _require_input_datetime(
            recorded_at,
            "simulation-horizon release recorded_at",
        )
        with _write_transaction(self._engine) as connection:
            try:
                durable_attempt = load_submission_attempt(
                    connection,
                    result.submission.submission_attempt_id,
                )
            except SubmissionAttemptPersistenceError as error:
                raise ReservationLifecyclePersistenceError(
                    "simulation horizon attempt is malformed"
                ) from error
            if durable_attempt is None:
                raise ReservationLifecyclePersistenceError(
                    "simulation horizon attempt is not durable"
                )
            lifecycle = self._lock(
                connection,
                reservation_id=durable_attempt.preparation.reservation_id,
                authorization_id=durable_attempt.preparation.authorization_id,
                fence=fence,
                checked_at=recorded_at,
            )
            attempt = self._attempt(lifecycle, durable_attempt.attempt_id)
            if (
                attempt.state is not SubmissionAttemptState.CONFIRMED
                or attempt.resolution is not None
            ):
                raise ReservationLifecyclePersistenceError(
                    "durable simulation horizon requires an exact CONFIRMED attempt"
                )
            persisted_order = _persist_order_state(
                connection,
                result.order_state,
                attempt,
                lifecycle.authorization,
            )
            _require_simulation_execution_coverage(
                connection,
                history=lifecycle.history,
                authorization=lifecycle.authorization,
                attempt=attempt,
                order_state=persisted_order,
                account_id=_require_text(
                    lifecycle.reservation_row["account_id"],
                    "reservation account ID",
                    maximum=64,
                ),
                execution_currency=lifecycle.reservation.currency,
            )
            horizon, horizon_inserted = persist_simulation_horizon_fact(
                connection,
                result=result,
                replay=replay,
                replay_events=replay_events,
                replay_watermarks=replay_watermarks,
                manifest=replay_manifest,
                reservation=lifecycle.reservation,
                authorization=lifecycle.authorization,
                attempt=attempt,
                recorded_at=recorded_at,
            )
            last_order_event = persisted_order.broker_events[-1]
            existing = _existing_fact(
                lifecycle,
                reason=ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
                finality_reference=horizon.horizon_reference,
                source_sha256=horizon.horizon_source_sha256,
                order_id=horizon.order_id,
                attempt_id=horizon.attempt_id,
                order_event_id=horizon.final_order_event_id,
            )
            if existing is not None:
                if horizon_inserted:
                    raise ReservationLifecyclePersistenceError(
                        "simulation-horizon release predates its immutable proof"
                    )
                if (
                    existing.attempt_sha256 != horizon.attempt_sha256
                    or existing.order_state_sha256 != horizon.order_state_sha256
                    or existing.order_event_sha256 != horizon.final_order_event_sha256
                    or existing.occurred_at != horizon.horizon_at
                ):
                    raise ReservationLifecyclePersistenceError(
                        "simulation-horizon retry changed reconstructed proof evidence"
                    )
                return _retry_result(lifecycle, existing)
            if not horizon_inserted:
                raise ReservationLifecyclePersistenceError(
                    "simulation-horizon proof exists without its atomic release"
                )
            _require_mutable(lifecycle)
            fact = record_simulation_horizon_final_release(
                reservation=lifecycle.reservation,
                authorization=lifecycle.authorization,
                attempt=attempt,
                order_state=persisted_order,
                last_order_event=last_order_event,
                horizon_reference=horizon.horizon_reference,
                horizon_source_sha256=horizon.horizon_source_sha256,
                horizon_at=horizon.horizon_at,
                recorded_at=recorded_at,
                prior_releases=lifecycle.history,
            )
            return _insert_release(connection, lifecycle, fact)

    def _lock(
        self,
        connection: Connection,
        *,
        reservation_id: str,
        authorization_id: str,
        fence: AccountFence,
        checked_at: datetime,
    ) -> _LockedLifecycle:
        if type(fence) is not AccountFence:
            raise ReservationLifecycleError("lifecycle mutation requires an exact fence")
        receipt = self._coordinator.revalidate_in_transaction(
            connection,
            fence,
            checked_at=checked_at,
        )
        if type(receipt) is not AccountFenceReceipt:
            raise ReservationLifecyclePersistenceError(
                "SQL fence validator returned non-canonical receipt evidence"
            )
        receipt._validate()
        if receipt.fence != fence or receipt.validated_at != checked_at:
            raise ReservationLifecyclePersistenceError(
                "SQL fence receipt does not bind the requested fence and instant"
            )
        row = _locked_reservation_row(connection, reservation_id)
        if row["account_id"] != fence.account_id:
            raise ReservationLifecyclePersistenceError(
                "reservation and current coordinator fence belong to different accounts"
            )
        return _lifecycle_from_locked_row(connection, row, authorization_id)

    @staticmethod
    def _attempt(
        lifecycle: _LockedLifecycle,
        attempt_id: str,
    ) -> CanonicalSubmissionAttempt:
        matches = tuple(
            attempt for attempt in lifecycle.attempts if attempt.attempt_id == attempt_id
        )
        if len(matches) != 1:
            raise ReservationLifecyclePersistenceError(
                "release attempt is missing from the complete parent snapshot"
            )
        attempt = matches[0]
        if attempt.preparation.authorization_id != lifecycle.authorization.decision_id:
            raise ReservationLifecyclePersistenceError(
                "release attempt belongs to another reservation child"
            )
        child_attempts = tuple(
            candidate
            for candidate in lifecycle.attempts
            if candidate.preparation.authorization_id == lifecycle.authorization.decision_id
        )
        if not child_attempts or child_attempts[-1].attempt_id != attempt.attempt_id:
            raise ReservationLifecyclePersistenceError(
                "reservation finality requires the latest submission attempt for its child"
            )
        return attempt

    @staticmethod
    def _persist_accounting_source(
        connection: Connection,
        lifecycle: _LockedLifecycle,
        order_state: CanonicalOrderState,
        event: BrokerOrderEvent,
        *,
        accounting_reference: str,
        accounting_source_sha256: str,
        accounted_at: datetime,
    ) -> None:
        try:
            expected_matches = tuple(
                entry
                for entry in reduce_execution_ledger(
                    order_states=(order_state,),
                    execution_currency=lifecycle.reservation.currency,
                ).entries
                if entry.reference_id == event.event_id
            )
        except (LedgerReductionError, Phase2LedgerPersistenceError) as error:
            raise ReservationLifecyclePersistenceError(
                "execution release requires canonical accounting evidence"
            ) from error
        if len(expected_matches) != 1:
            raise ReservationLifecyclePersistenceError(
                "accounting finality does not bind exact reducer-derived execution economics"
            )
        entry = expected_matches[0]
        if (
            entry.entry_id != accounting_reference
            or entry.source_sha256 != event.semantic_sha256
            or entry.semantic_sha256 != accounting_source_sha256
            or entry.recorded_at > accounted_at
        ):
            raise ReservationLifecyclePersistenceError(
                "accounting finality does not bind exact reducer-derived execution economics"
            )
        try:
            persist_phase2_ledger_entry(
                connection,
                account_id=str(lifecycle.reservation_row["account_id"]),
                entry=entry,
            )
        except Phase2LedgerPersistenceError as error:
            raise ReservationLifecyclePersistenceError(
                "accounting finality does not bind exact reducer-derived execution economics"
            ) from error

    @staticmethod
    def _freeze_for_correction(
        connection: Connection,
        lifecycle: _LockedLifecycle,
    ) -> None:
        if lifecycle.snapshot.persisted_state is ReservationCapacityState.FROZEN:
            return
        result = connection.execute(
            sa.update(phase2_batch_reservations)
            .where(
                phase2_batch_reservations.c.reservation_id == lifecycle.reservation.reservation_id,
                phase2_batch_reservations.c.state_version == lifecycle.snapshot.state_version,
            )
            .values(
                state=ReservationCapacityState.FROZEN.value,
                state_version=lifecycle.snapshot.state_version + 1,
                released_at=None,
            )
        )
        if result.rowcount != 1:
            raise ReservationLifecyclePersistenceError(
                "reservation head changed while applying correction freeze"
            )
