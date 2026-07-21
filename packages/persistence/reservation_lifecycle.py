"""Durable, fence-bound reservation release and remaining-capacity projections."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from itertools import pairwise, product
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.backtest.simulated_broker import SimulatedBrokerResult
from packages.backtest.simulation_horizon import SimulationHorizonFact
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.batch_risk import BatchRiskAuthorization, BatchRiskReservation
from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import exact_decimal_subtract, exact_decimal_sum
from packages.domain.ledger_reducer import LedgerReductionError, reduce_execution_ledger
from packages.domain.market_batch import MarketWatermark
from packages.domain.models import MarketEvent, require_utc
from packages.domain.order_reducer import (
    ORDER_REDUCER_CONTRACT_VERSION,
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    CanonicalOrderStatus,
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
    _bind_attempt,
    _bind_order,
    _execution_predecessor,
    project_reservation_capacity,
    record_approval_expired_unsent_release,
    record_broker_rejected_release,
    record_execution_accounted_release,
    record_simulation_horizon_final_release,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    UnknownSubmissionResolution,
    reduce_submission_attempt,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.batch_risk import (
    account_observation_watermark,
    load_batch_risk_decision,
)
from packages.persistence.capacity_ordering import (
    ORDER_EVENT_VISIBILITY_KIND,
    RESERVATION_RELEASE_VISIBILITY_KIND,
    SUBMISSION_EVENT_VISIBILITY_KIND,
    CapacityVisibilityError,
    capacity_visibility_values,
    verify_capacity_visibility,
)
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
    phase2_batch_decisions,
    phase2_batch_reservations,
    phase2_logical_orders,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
    phase2_submission_attempt_events,
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
    visible_after_observation_sequence: int


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
    event_rows = tuple(
        connection.execute(
            sa.select(phase2_order_events)
            .where(phase2_order_events.c.order_id == attempt.order_id)
            .order_by(phase2_order_events.c.broker_sequence)
        )
        .mappings()
        .all()
    )
    decoded = tuple(_order_event_from_row(event_row) for event_row in event_rows)
    try:
        visibility_markers = tuple(
            verify_capacity_visibility(
                account_id=attempt.preparation.risk_decision.account_id,
                fact_kind=ORDER_EVENT_VISIBILITY_KIND,
                fact_sha256=event.semantic_sha256,
                visible_after_observation_sequence=event_row["visible_after_observation_sequence"],
                capacity_visibility_sha256_value=event_row["capacity_visibility_sha256"],
            )
            for event_row, (event, _cancel_request) in zip(
                event_rows,
                decoded,
                strict=True,
            )
        )
    except CapacityVisibilityError as error:
        raise ReservationLifecyclePersistenceError(
            "order event visibility binding is malformed"
        ) from error
    if any(
        marker
        > account_observation_watermark(
            connection,
            attempt.preparation.risk_decision.account_id,
        )
        for marker in visibility_markers
    ):
        raise ReservationLifecyclePersistenceError(
            "order event visibility exceeds the durable account observation watermark"
        )
    if any(current < previous for previous, current in pairwise(visibility_markers)):
        raise ReservationLifecyclePersistenceError("order event visibility sequence regresses")
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
    *,
    visible_after_observation_sequence: int,
) -> CanonicalOrderState:
    if (
        type(visible_after_observation_sequence) is not int
        or visible_after_observation_sequence < 0
    ):
        raise ReservationLifecyclePersistenceError(
            "order event visibility sequence must be non-negative"
        )
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
            existing_row = (
                connection.execute(
                    sa.select(phase2_order_events).where(
                        phase2_order_events.c.event_id == event.event_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing_row is not None:
                if _order_event_from_row(existing_row) != (event, cancel_request):
                    raise ReservationLifecyclePersistenceError(
                        "order event conflicts with immutable SQL history"
                    )
                continue
            connection.execute(
                sa.insert(phase2_order_events).values(
                    **immutable_order_event_values(event, cancel_request=cancel_request),
                    **capacity_visibility_values(
                        account_id=attempt.preparation.risk_decision.account_id,
                        fact_kind=ORDER_EVENT_VISIBILITY_KIND,
                        fact_sha256=event.semantic_sha256,
                        visible_after_observation_sequence=(visible_after_observation_sequence),
                    ),
                )
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
    rows = tuple(
        connection.execute(
            sa.select(phase2_reservation_release_events).where(
                phase2_reservation_release_events.c.reservation_id == reservation.reservation_id
            )
        )
        .mappings()
        .all()
    )
    facts = tuple(reservation_release_from_row(row) for row in rows)
    ordered = tuple(sorted(facts, key=lambda fact: fact.sequence_number))
    rows_by_id = {
        _require_text(row["release_event_id"], "release event ID", maximum=64): row for row in rows
    }
    release_account_id = _require_text(
        connection.scalar(
            sa.select(phase2_batch_reservations.c.account_id).where(
                phase2_batch_reservations.c.reservation_id == reservation.reservation_id
            )
        ),
        "reservation account ID",
        maximum=64,
    )
    try:
        visibility_markers = tuple(
            verify_capacity_visibility(
                account_id=release_account_id,
                fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
                fact_sha256=fact.semantic_sha256,
                visible_after_observation_sequence=rows_by_id[fact.release_event_id][
                    "visible_after_observation_sequence"
                ],
                capacity_visibility_sha256_value=rows_by_id[fact.release_event_id][
                    "capacity_visibility_sha256"
                ],
            )
            for fact in ordered
        )
    except CapacityVisibilityError as error:
        raise ReservationLifecyclePersistenceError(
            "reservation release visibility binding is malformed"
        ) from error
    if any(
        marker > account_observation_watermark(connection, release_account_id)
        for marker in visibility_markers
    ):
        raise ReservationLifecyclePersistenceError(
            "reservation release visibility exceeds the durable account observation watermark"
        )
    project_reservation_capacity(reservation, ordered)
    if any(current < previous for previous, current in pairwise(visibility_markers)):
        raise ReservationLifecyclePersistenceError(
            "reservation release visibility sequence regresses"
        )
    if any(
        marker > 0 and current.recorded_at < previous.recorded_at
        for previous, current, marker in zip(
            ordered,
            ordered[1:],
            visibility_markers[1:],
            strict=False,
        )
    ):
        raise ReservationLifecyclePersistenceError(
            "reservation release history regresses its recorded time"
        )
    return ordered


def _legacy_release_ids(
    connection: Connection,
    history: tuple[ReservationReleaseFact, ...],
) -> frozenset[str]:
    if not history:
        return frozenset()
    rows = connection.execute(
        sa.select(
            phase2_reservation_release_events.c.release_event_id,
            phase2_reservation_release_events.c.visible_after_observation_sequence,
        ).where(
            phase2_reservation_release_events.c.release_event_id.in_(
                tuple(fact.release_event_id for fact in history)
            )
        )
    ).mappings()
    markers = {
        _require_text(row["release_event_id"], "release event ID", maximum=64): _require_int(
            row["visible_after_observation_sequence"],
            "release visibility sequence",
            allow_zero=True,
        )
        for row in rows
    }
    if len(markers) != len(history):
        raise ReservationLifecyclePersistenceError(
            "reservation release visibility metadata is incomplete"
        )
    return frozenset(release_id for release_id, marker in markers.items() if marker == 0)


def load_reservation_release_history(
    connection: Connection,
    reservation_id: str,
) -> tuple[ReservationReleaseFact, ...]:
    """Strictly load and authenticate one release chain and its durable evidence."""

    return verify_reservation_release_integrity(connection, reservation_id)


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


_CORRECTION_CLOSURE_REASONS = frozenset(
    {
        ReservationReleaseReason.RECONCILED_TERMINAL,
        ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
    }
)


def _latest_attempts_by_authorization(
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> tuple[CanonicalSubmissionAttempt, ...]:
    latest: dict[str, CanonicalSubmissionAttempt] = {}
    for attempt in attempts:
        authorization_id = attempt.preparation.authorization_id
        current = latest.get(authorization_id)
        if current is None or attempt.attempt_number > current.attempt_number:
            latest[authorization_id] = attempt
    return tuple(latest[key] for key in sorted(latest))


def _possible_order_state_digests(
    order_state: CanonicalOrderState,
    *,
    required_event: BrokerOrderEvent,
    recorded_at: datetime,
) -> frozenset[str]:
    """Return canonical durable prefixes that could have backed one release fact."""

    required_index = order_state.broker_events.index(required_event)
    digests: set[str] = set()
    for end in range(required_index + 1, len(order_state.broker_events) + 1):
        events = order_state.broker_events[:end]
        if events[-1].received_at > recorded_at:
            break
        cancel_request = (
            order_state.cancel_request
            if any(event.kind is BrokerOrderEventKind.CANCELED for event in events)
            else None
        )
        try:
            prefix = reduce_order_lifecycle(
                submission=order_state.submission,
                broker_events=events,
                cancel_request=cancel_request,
            )
        except OrderLifecycleError as error:  # pragma: no cover - full state is canonical
            raise ReservationLifecyclePersistenceError(
                "correction evidence cannot reconstruct its canonical order prefix"
            ) from error
        digests.add(prefix.semantic_sha256)
    return frozenset(digests)


_UNRESOLVED_BROKER_EFFECT_STATES = frozenset(
    {
        SubmissionAttemptState.PENDING,
        SubmissionAttemptState.IN_FLIGHT,
        SubmissionAttemptState.UNKNOWN,
        SubmissionAttemptState.ABANDONED,
    }
)


def _release_attempt_has_broker_effect(
    fact: ReservationReleaseFact,
    attempt: CanonicalSubmissionAttempt,
) -> bool:
    """Authenticate reason-specific submission finality and identify order evidence."""

    if attempt.state in _UNRESOLVED_BROKER_EFFECT_STATES:
        raise ReservationLifecyclePersistenceError(
            "broker-effect release names an unresolved or never-dispatched attempt"
        )
    if fact.reason is ReservationReleaseReason.BROKER_REJECTED:
        if attempt.state is SubmissionAttemptState.CONFIRMED:
            return True
        if (
            attempt.state is SubmissionAttemptState.RESOLVED
            and attempt.resolution is UnknownSubmissionResolution.BROKER_REJECTED
        ):
            return True
        raise ReservationLifecyclePersistenceError(
            "broker rejection release lacks confirmed rejection evidence"
        )
    if fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED:
        if attempt.state is SubmissionAttemptState.CONFIRMED:
            return True
        if (
            attempt.state is SubmissionAttemptState.RESOLVED
            and attempt.resolution is UnknownSubmissionResolution.BROKER_ACCEPTED
        ):
            return True
        raise ReservationLifecyclePersistenceError(
            "execution release lacks confirmed broker acceptance"
        )
    if fact.reason is ReservationReleaseReason.SIMULATION_HORIZON_FINAL:
        if attempt.state is SubmissionAttemptState.CONFIRMED and attempt.resolution is None:
            return True
        raise ReservationLifecyclePersistenceError(
            "simulation-horizon release lacks its exact confirmed attempt"
        )
    if fact.reason is ReservationReleaseReason.RECONCILED_TERMINAL:
        if (
            attempt.state is SubmissionAttemptState.RESOLVED
            and attempt.resolution is UnknownSubmissionResolution.NOT_SUBMITTED
        ):
            return False
        if attempt.state is SubmissionAttemptState.CONFIRMED or (
            attempt.state is SubmissionAttemptState.RESOLVED
            and attempt.resolution
            in {
                UnknownSubmissionResolution.BROKER_ACCEPTED,
                UnknownSubmissionResolution.BROKER_REJECTED,
            }
        ):
            return True
        raise ReservationLifecyclePersistenceError(
            "terminal reconciliation lacks resolved submission evidence"
        )
    raise ReservationLifecyclePersistenceError(
        "release attempt verifier received a reason without attempt evidence"
    )


def _exact_release_order_evidence(
    connection: Connection,
    *,
    fact: ReservationReleaseFact,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
) -> tuple[CanonicalOrderState, BrokerOrderEvent]:
    order_state = load_canonical_order_state(connection, attempt.attempt_id)
    if order_state is None:
        raise ReservationLifecyclePersistenceError(
            "broker-effect release lacks its durable logical order"
        )
    try:
        _bind_order(authorization, attempt, order_state)
    except ReservationLifecycleError as error:
        raise ReservationLifecyclePersistenceError(
            "broker-effect release order conflicts with its exact attempt"
        ) from error
    matches = tuple(
        event for event in order_state.broker_events if event.event_id == fact.order_event_id
    )
    if len(matches) != 1:
        raise ReservationLifecyclePersistenceError(
            "broker-effect release does not bind exact durable order-event evidence"
        )
    event = matches[0]
    if (
        fact.order_id != order_state.submission.order_id
        or fact.order_event_sha256 != event.semantic_sha256
        or fact.order_state_sha256
        not in _possible_order_state_digests(
            order_state,
            required_event=event,
            recorded_at=fact.recorded_at,
        )
    ):
        raise ReservationLifecyclePersistenceError(
            "broker-effect release does not bind exact durable order-event evidence"
        )
    return order_state, event


_MAX_EXPIRY_SNAPSHOT_CANDIDATES = 4096


def _parent_attempt_snapshot_sha256(
    parent_decision_id: str,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> str:
    """Reproduce the expiry factory's digest for one exact parent snapshot."""

    return hashlib.sha256(
        canonical_json_bytes(
            (
                RESERVATION_LIFECYCLE_CONTRACT_VERSION,
                "complete_parent_attempt_snapshot",
                parent_decision_id,
                tuple(attempt.semantic_sha256 for attempt in attempts),
            )
        )
    ).hexdigest()


def _release_visibility_marker(
    connection: Connection,
    *,
    account_id: str,
    fact: ReservationReleaseFact,
) -> int:
    row = (
        connection.execute(
            sa.select(
                phase2_reservation_release_events.c.visible_after_observation_sequence,
                phase2_reservation_release_events.c.capacity_visibility_sha256,
            ).where(phase2_reservation_release_events.c.release_event_id == fact.release_event_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ReservationLifecyclePersistenceError(
            "approval-expiry release lacks its durable visibility evidence"
        )
    try:
        marker = verify_capacity_visibility(
            account_id=account_id,
            fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
            fact_sha256=fact.semantic_sha256,
            visible_after_observation_sequence=row["visible_after_observation_sequence"],
            capacity_visibility_sha256_value=row["capacity_visibility_sha256"],
        )
    except CapacityVisibilityError as error:
        raise ReservationLifecyclePersistenceError(
            "approval-expiry release visibility binding is malformed"
        ) from error
    if marker > account_observation_watermark(connection, account_id):
        raise ReservationLifecyclePersistenceError(
            "approval-expiry release visibility exceeds the durable account watermark"
        )
    return marker


def _event_visibility_relation(
    *,
    event_marker: int,
    event_recorded_at: datetime,
    release_marker: int,
    release_recorded_at: datetime,
) -> int:
    """Order one event before (0), at (1), or after (2) a release cut."""

    if release_marker == 0:
        # A current authenticated mutation was necessarily written after migrated
        # v3 evidence, even if its business timestamp is backdated.
        if event_marker > 0:
            return 2
        if event_recorded_at < release_recorded_at:
            return 0
        if event_recorded_at > release_recorded_at:
            return 2
        # Equal-time migrated rows need source-hash disambiguation because v3
        # did not carry an authenticated account observation sequence.
        return 1
    if event_marker < release_marker:
        return 0
    if event_marker > release_marker:
        return 2
    # Same-watermark v4 mutations have no finer authenticated ordering fact.
    # Caller-supplied recorded times can be backdated, so the source digest—not
    # those timestamps—must select the historical prefix.
    return 1


def _causal_attempt_prefixes(
    connection: Connection,
    *,
    account_id: str,
    attempt: CanonicalSubmissionAttempt,
    release_marker: int,
    release_recorded_at: datetime,
) -> tuple[CanonicalSubmissionAttempt | None, ...]:
    rows = tuple(
        connection.execute(
            sa.select(
                phase2_submission_attempt_events.c.event_id,
                phase2_submission_attempt_events.c.sequence_number,
                phase2_submission_attempt_events.c.semantic_sha256,
                phase2_submission_attempt_events.c.visible_after_observation_sequence,
                phase2_submission_attempt_events.c.capacity_visibility_sha256,
            )
            .where(phase2_submission_attempt_events.c.attempt_id == attempt.attempt_id)
            .order_by(phase2_submission_attempt_events.c.sequence_number)
        )
        .mappings()
        .all()
    )
    if len(rows) != len(attempt.events):
        raise ReservationLifecyclePersistenceError(
            "approval-expiry replay lacks a complete durable attempt history"
        )
    relations: list[int] = []
    try:
        for event, row in zip(attempt.events, rows, strict=True):
            if (
                row["event_id"] != event.event_id
                or row["sequence_number"] != event.sequence_number
                or row["semantic_sha256"] != event.semantic_sha256
            ):
                raise ReservationLifecyclePersistenceError(
                    "approval-expiry replay conflicts with durable attempt evidence"
                )
            event_marker = verify_capacity_visibility(
                account_id=account_id,
                fact_kind=SUBMISSION_EVENT_VISIBILITY_KIND,
                fact_sha256=event.semantic_sha256,
                visible_after_observation_sequence=row["visible_after_observation_sequence"],
                capacity_visibility_sha256_value=row["capacity_visibility_sha256"],
            )
            relations.append(
                _event_visibility_relation(
                    event_marker=event_marker,
                    event_recorded_at=event.recorded_at,
                    release_marker=release_marker,
                    release_recorded_at=release_recorded_at,
                )
            )
    except CapacityVisibilityError as error:
        raise ReservationLifecyclePersistenceError(
            "approval-expiry attempt visibility binding is malformed"
        ) from error
    if relations != sorted(relations):
        raise ReservationLifecyclePersistenceError(
            "approval-expiry attempt visibility cannot form a causal prefix"
        )
    minimum_length = sum(relation == 0 for relation in relations)
    maximum_length = next(
        (index for index, relation in enumerate(relations) if relation == 2),
        len(relations),
    )
    candidates: list[CanonicalSubmissionAttempt | None] = []
    for prefix_length in range(minimum_length, maximum_length + 1):
        if prefix_length == 0:
            candidates.append(None)
            continue
        try:
            candidates.append(
                reduce_submission_attempt(
                    attempt.preparation,
                    attempt.events[:prefix_length],
                )
            )
        except SubmissionAttemptError as error:  # pragma: no cover - full history is canonical
            raise ReservationLifecyclePersistenceError(
                "approval-expiry replay cannot reconstruct a canonical attempt prefix"
            ) from error
    return tuple(candidates)


def _verify_approval_expired_unsent_release(
    connection: Connection,
    *,
    account_id: str,
    reservation: BatchRiskReservation,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
    prior_releases: tuple[ReservationReleaseFact, ...],
    fact: ReservationReleaseFact,
) -> None:
    """Replay an expiry against the exact causally visible parent snapshot."""

    release_marker = _release_visibility_marker(
        connection,
        account_id=account_id,
        fact=fact,
    )
    per_attempt = tuple(
        _causal_attempt_prefixes(
            connection,
            account_id=account_id,
            attempt=attempt,
            release_marker=release_marker,
            release_recorded_at=fact.recorded_at,
        )
        for attempt in attempts
    )
    candidate_count = 1
    for candidates in per_attempt:
        candidate_count *= len(candidates)
        if candidate_count > _MAX_EXPIRY_SNAPSHOT_CANDIDATES:
            raise ReservationLifecyclePersistenceError(
                "approval-expiry causal snapshot is too ambiguous to authenticate"
            )

    exact_matches = 0
    seen_snapshots: set[tuple[str, ...]] = set()
    for combination in product(*per_attempt):
        snapshot = tuple(attempt for attempt in combination if attempt is not None)
        snapshot_sha256s = tuple(attempt.semantic_sha256 for attempt in snapshot)
        if snapshot_sha256s in seen_snapshots:
            continue
        seen_snapshots.add(snapshot_sha256s)
        ordering = tuple(
            (attempt.order_id, attempt.attempt_number, attempt.attempt_id) for attempt in snapshot
        )
        attempt_ids = tuple(attempt.attempt_id for attempt in snapshot)
        if (
            ordering != tuple(sorted(ordering))
            or len(ordering) != len(set(ordering))
            or len(attempt_ids) != len(set(attempt_ids))
            or any(
                attempt.parent_decision_id != reservation.parent_decision_id for attempt in snapshot
            )
        ):
            raise ReservationLifecyclePersistenceError(
                "approval-expiry parent attempt snapshot is not complete and canonical"
            )
        if (
            _parent_attempt_snapshot_sha256(
                reservation.parent_decision_id,
                snapshot,
            )
            != fact.source_sha256
        ):
            continue
        try:
            expected = record_approval_expired_unsent_release(
                reservation=reservation,
                authorization=_authorization(reservation, fact.authorization_id),
                parent_attempts=snapshot,
                finality_reference=fact.finality_reference,
                observed_at=fact.occurred_at,
                recorded_at=fact.recorded_at,
                prior_releases=prior_releases,
            )
        except ReservationLifecycleError:
            continue
        if expected == fact:
            exact_matches += 1
    if exact_matches != 1:
        raise ReservationLifecyclePersistenceError(
            "approval-expiry release lacks one exact causal unsent snapshot"
        )


def _verify_broker_effect_release_integrity(
    connection: Connection,
    *,
    account_id: str,
    reservation: BatchRiskReservation,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
    history: tuple[ReservationReleaseFact, ...],
) -> None:
    """Replay reason-specific evidence for every attempt-backed capacity release."""

    attempts_by_id = {attempt.attempt_id: attempt for attempt in attempts}
    for index, fact in enumerate(history):
        if fact.reason is ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT:
            _verify_approval_expired_unsent_release(
                connection,
                account_id=account_id,
                reservation=reservation,
                attempts=attempts,
                prior_releases=history[:index],
                fact=fact,
            )
            continue
        if fact.attempt_id is None:
            raise ReservationLifecyclePersistenceError(
                "attempt-backed release omitted its durable submission identity"
            )
        attempt = attempts_by_id.get(fact.attempt_id)
        if attempt is None:
            raise ReservationLifecyclePersistenceError(
                "attempt-backed release names a missing durable submission"
            )
        authorization = _authorization(reservation, fact.authorization_id)
        try:
            _bind_attempt(reservation, authorization, attempt)
        except ReservationLifecycleError as error:
            raise ReservationLifecyclePersistenceError(
                "release attempt conflicts with its reservation authorization"
            ) from error
        if fact.attempt_sha256 != attempt.semantic_sha256:
            raise ReservationLifecyclePersistenceError(
                "release does not bind the exact durable attempt state"
            )
        has_broker_effect = _release_attempt_has_broker_effect(fact, attempt)
        if not has_broker_effect:
            reconciliation_sha256 = attempt.events[-1].reconciliation_sha256
            if (
                fact.order_id is not None
                or fact.order_state_sha256 is not None
                or fact.order_event_id is not None
                or fact.order_event_sha256 is not None
                or reconciliation_sha256 is None
                or fact.source_sha256 != reconciliation_sha256
                or fact.occurred_at < attempt.as_of
            ):
                raise ReservationLifecyclePersistenceError(
                    "not-submitted release conflicts with exact reconciliation evidence"
                )
            continue
        order_state, event = _exact_release_order_evidence(
            connection,
            fact=fact,
            authorization=authorization,
            attempt=attempt,
        )
        if fact.reason is ReservationReleaseReason.BROKER_REJECTED:
            if (
                event.kind is not BrokerOrderEventKind.REJECTED
                or order_state.status is not CanonicalOrderStatus.REJECTED
                or order_state.broker_events[-1] != event
                or fact.finality_reference != event.event_id
                or fact.source_sha256 != event.semantic_sha256
                or fact.occurred_at != event.received_at
            ):
                raise ReservationLifecyclePersistenceError(
                    "broker rejection release conflicts with its terminal broker event"
                )
        elif fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED:
            if event.kind not in {
                BrokerOrderEventKind.EXECUTION,
                BrokerOrderEventKind.EXECUTION_CORRECTION,
            }:
                raise ReservationLifecyclePersistenceError(
                    "execution release names a non-execution broker event"
                )
            _authenticate_execution_accounting_fact(
                fact,
                attempt=attempt,
                order_state=order_state,
                event=event,
            )
        elif fact.reason is ReservationReleaseReason.RECONCILED_TERMINAL and (
            order_state.status
            not in {
                CanonicalOrderStatus.FILLED,
                CanonicalOrderStatus.CANCELED,
                CanonicalOrderStatus.REJECTED,
            }
            or order_state.broker_events[-1] != event
            or fact.occurred_at <= order_state.as_of
        ):
            raise ReservationLifecyclePersistenceError(
                "terminal release conflicts with exact reconciled order evidence"
            )


def verify_reservation_release_integrity(
    connection: Connection,
    reservation_id: str,
) -> tuple[ReservationReleaseFact, ...]:
    """Strictly authenticate one release chain against attempt and order evidence."""

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
    history = _release_history(connection, decision.reservation)
    _verify_broker_effect_release_integrity(
        connection,
        account_id=_require_text(row["account_id"], "reservation account ID", maximum=64),
        reservation=decision.reservation,
        attempts=_parent_attempts(connection, decision.decision_id, lock=False),
        history=history,
    )
    return history


def _authenticate_execution_accounting_fact(
    fact: ReservationReleaseFact,
    *,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    event: BrokerOrderEvent,
) -> None:
    assert event.execution_id is not None
    assert event.execution_revision is not None
    assert event.quantity is not None
    if (
        fact.reason is not ReservationReleaseReason.EXECUTION_ACCOUNTED
        or fact.authorization_id != attempt.preparation.authorization_id
        or fact.attempt_id != attempt.attempt_id
        or fact.attempt_sha256 != attempt.semantic_sha256
        or fact.order_id != order_state.submission.order_id
        or fact.order_event_id != event.event_id
        or fact.order_event_sha256 != event.semantic_sha256
        or fact.execution_id != event.execution_id
        or fact.execution_revision != event.execution_revision
        or fact.execution_head_quantity != event.quantity
        or fact.occurred_at < event.received_at
        or fact.order_state_sha256
        not in _possible_order_state_digests(
            order_state,
            required_event=event,
            recorded_at=fact.recorded_at,
        )
    ):
        raise ReservationLifecyclePersistenceError(
            "execution correction accounting does not bind its exact durable revision"
        )


def _authenticate_correction_accounting_order(
    history: tuple[ReservationReleaseFact, ...],
    accounting: ReservationReleaseFact,
    *,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    correction: BrokerOrderEvent,
    predecessor: BrokerOrderEvent,
    legacy_writer: bool,
) -> None:
    """Authenticate the exact ordered predecessor coverage for a correction release."""

    _authenticate_execution_accounting_fact(
        accounting,
        attempt=attempt,
        order_state=order_state,
        event=correction,
    )
    assert correction.execution_id is not None
    assert correction.quantity is not None
    assert predecessor.execution_revision is not None
    assert predecessor.quantity is not None
    prior = tuple(
        fact
        for fact in history
        if fact.sequence_number < accounting.sequence_number
        and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
        and fact.authorization_id == attempt.preparation.authorization_id
        and fact.attempt_id == attempt.attempt_id
        and fact.order_id == order_state.submission.order_id
        and fact.execution_id == correction.execution_id
        and fact.accounted_quantity is not None
    )
    if legacy_writer:
        prior_accounted = exact_decimal_sum(
            fact.accounted_quantity for fact in prior if fact.accounted_quantity is not None
        )
        expected_delta = exact_decimal_subtract(correction.quantity, prior_accounted)
        if accounting.accounted_quantity != expected_delta or expected_delta <= 0:
            raise ReservationLifecyclePersistenceError(
                "legacy execution correction accounting violates its cumulative baseline"
            )
        return
    predecessor_matches = tuple(
        fact
        for fact in prior
        if fact.order_event_id == predecessor.event_id
        and fact.execution_revision == predecessor.execution_revision
        and fact.execution_head_quantity == predecessor.quantity
    )
    if len(predecessor_matches) != 1:
        raise ReservationLifecyclePersistenceError(
            "execution correction accounting lacks its exact predecessor release"
        )
    _authenticate_execution_accounting_fact(
        predecessor_matches[0],
        attempt=attempt,
        order_state=order_state,
        event=predecessor,
    )
    cumulative_accounted = exact_decimal_sum(
        fact.accounted_quantity for fact in prior if fact.accounted_quantity is not None
    )
    latest_revision = max((fact.execution_revision or 0 for fact in prior), default=0)
    expected_delta = exact_decimal_subtract(correction.quantity, predecessor.quantity)
    if (
        cumulative_accounted != predecessor.quantity
        or latest_revision != predecessor.execution_revision
        or accounting.accounted_quantity != expected_delta
        or expected_delta <= 0
    ):
        raise ReservationLifecyclePersistenceError(
            "execution correction accounting violates exact predecessor ordering"
        )


def _is_exact_correction_closure(
    fact: ReservationReleaseFact,
    *,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    correction: BrokerOrderEvent,
) -> bool:
    if (
        fact.reason not in _CORRECTION_CLOSURE_REASONS
        or fact.authorization_id != attempt.preparation.authorization_id
        or fact.attempt_id != attempt.attempt_id
        or fact.order_id != order_state.submission.order_id
        or fact.occurred_at < correction.received_at
    ):
        return False
    event_matches = tuple(
        event for event in order_state.broker_events if event.event_id == fact.order_event_id
    )
    if (
        fact.attempt_sha256 != attempt.semantic_sha256
        or len(event_matches) != 1
        or event_matches[0].broker_sequence < correction.broker_sequence
        or fact.order_event_sha256 != event_matches[0].semantic_sha256
        or fact.order_state_sha256
        not in _possible_order_state_digests(
            order_state,
            required_event=event_matches[0],
            recorded_at=fact.recorded_at,
        )
    ):
        raise ReservationLifecyclePersistenceError(
            "execution correction closure does not bind exact durable order evidence"
        )
    return True


def _unresolved_nonmonotone_correction_material(
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    history: tuple[ReservationReleaseFact, ...],
    *,
    legacy_release_ids: frozenset[str] = frozenset(),
) -> tuple[tuple[object, ...], ...]:
    """Authenticate every historical correction and retain unresolved unsafe revisions."""

    corrections: list[tuple[object, ...]] = []
    for event in order_state.broker_events:
        if event.kind is not BrokerOrderEventKind.EXECUTION_CORRECTION:
            continue
        predecessor = _execution_predecessor(order_state, event)
        assert predecessor is not None
        assert predecessor.quantity is not None
        assert event.quantity is not None
        exact_accounting = tuple(
            fact
            for fact in history
            if fact.order_event_id == event.event_id
            and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
        )
        if len(exact_accounting) > 1:
            raise ReservationLifecyclePersistenceError(
                "execution correction has duplicate accounting finality"
            )
        if exact_accounting:
            _authenticate_correction_accounting_order(
                history,
                exact_accounting[0],
                attempt=attempt,
                order_state=order_state,
                correction=event,
                predecessor=predecessor,
                legacy_writer=exact_accounting[0].release_event_id in legacy_release_ids,
            )
        if event.quantity > predecessor.quantity:
            continue
        if exact_accounting:  # pragma: no cover - authenticated positive delta above
            continue
        if any(
            _is_exact_correction_closure(
                fact,
                attempt=attempt,
                order_state=order_state,
                correction=event,
            )
            for fact in history
        ):
            continue
        prior_accounting = tuple(
            fact
            for fact in history
            if fact.authorization_id == attempt.preparation.authorization_id
            and fact.attempt_id == attempt.attempt_id
            and fact.order_id == order_state.submission.order_id
            and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
            and fact.execution_id == event.execution_id
        )
        corrections.append(
            (
                attempt.attempt_id,
                attempt.semantic_sha256,
                order_state.semantic_sha256,
                event.event_id,
                event.semantic_sha256,
                predecessor.semantic_sha256,
                tuple(fact.semantic_sha256 for fact in prior_accounting),
            )
        )
    return tuple(corrections)


def _correction_freeze_material(
    connection: Connection,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
    history: tuple[ReservationReleaseFact, ...],
) -> tuple[tuple[object, ...], ...]:
    corrections: list[tuple[object, ...]] = []
    for attempt in _latest_attempts_by_authorization(attempts):
        order_state = load_canonical_order_state(connection, attempt.attempt_id)
        if order_state is None:
            raise ReservationLifecyclePersistenceError(
                "correction freeze references a missing durable logical order"
            )
        corrections.extend(
            _unresolved_nonmonotone_correction_material(
                attempt,
                order_state,
                history,
                legacy_release_ids=_legacy_release_ids(connection, history),
            )
        )
    return tuple(sorted(corrections))


def _unsafe_correction_accounting_is_complete(
    connection: Connection,
    lifecycle: _LockedLifecycle,
    order_state: CanonicalOrderState,
    event: BrokerOrderEvent,
    correction_material: tuple[tuple[object, ...], ...],
) -> bool:
    """Allow quarantined accounting only when it completes an exact execution chain."""

    event_matches = tuple(
        candidate for candidate in order_state.broker_events if candidate.event_id == event.event_id
    )
    if len(event_matches) != 1 or event_matches[0] != event:
        raise ReservationLifecyclePersistenceError(
            "accounting event is not exact durable order-state evidence"
        )
    if not correction_material:  # pragma: no cover - caller only uses the quarantine path
        return True
    if (
        event.kind
        not in {
            BrokerOrderEventKind.EXECUTION,
            BrokerOrderEventKind.EXECUTION_CORRECTION,
        }
        or event.execution_id is None
    ):
        raise ReservationLifecyclePersistenceError(
            "execution accounting requires exact execution event evidence"
        )

    chain_event_ids = frozenset(
        candidate.event_id
        for candidate in order_state.broker_events
        if candidate.execution_id == event.execution_id
        and candidate.kind
        in {
            BrokerOrderEventKind.EXECUTION,
            BrokerOrderEventKind.EXECUTION_CORRECTION,
        }
    )
    try:
        chain_entries = tuple(
            entry
            for entry in reduce_execution_ledger(
                order_states=(order_state,),
                execution_currency=lifecycle.reservation.currency,
            ).entries
            if entry.reference_id in chain_event_ids
        )
    except LedgerReductionError as error:
        raise ReservationLifecyclePersistenceError(
            "execution release requires canonical accounting evidence"
        ) from error
    current_entries = tuple(
        entry for entry in chain_entries if entry.reference_id == event.event_id
    )
    account_id = str(lifecycle.reservation_row["account_id"])
    persisted_entry_ids: set[str] = set()
    for entry in chain_entries:
        persisted = load_phase2_ledger_entry(connection, entry.entry_id)
        if persisted is not None and persisted != (account_id, entry):
            raise ReservationLifecyclePersistenceError(
                "execution ledger entry conflicts with canonical revision economics"
            )
        if persisted == (account_id, entry):
            persisted_entry_ids.add(entry.entry_id)

    if len(current_entries) == 1 and all(
        entry.reference_id == event.event_id or entry.entry_id in persisted_entry_ids
        for entry in chain_entries
    ):
        return True

    expected_entry_ids = {entry.entry_id for entry in chain_entries}
    if persisted_entry_ids and persisted_entry_ids != expected_entry_ids:
        raise ReservationLifecyclePersistenceError(
            "execution catch-up would leave a partial execution revision ledger chain"
        )

    # An equal correction has no economic delta and therefore no ledger entry.
    # A newly discovered corrected chain with no accounting remains wholly absent.
    return False


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
    correction_material: tuple[tuple[object, ...], ...],
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
    correction_frozen = bool(correction_material)
    if correction_frozen:
        expected_correction_state = (
            ReservationCapacityState.RELEASED
            if projection.state is ReservationCapacityState.RELEASED
            else ReservationCapacityState.FROZEN
        )
        if state is not expected_correction_state:
            raise ReservationLifecyclePersistenceError(
                "reservation head is not quarantined by its durable correction history"
            )
    if not correction_frozen and state is not projection.state:
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
    *,
    lock_attempts: bool = True,
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
    attempts = _parent_attempts(connection, parent_decision_id, lock=lock_attempts)
    unknown = _unknown_authorization_ids(attempts)
    history = _release_history(connection, reservation)
    _verify_broker_effect_release_integrity(
        connection,
        account_id=_require_text(row["account_id"], "reservation account ID", maximum=64),
        reservation=reservation,
        attempts=attempts,
        history=history,
    )
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
    correction_material = _correction_freeze_material(
        connection,
        attempts,
        history,
    )
    snapshot = _snapshot_from_head(row, projection, unknown, correction_material)
    return _LockedLifecycle(
        reservation_row=row,
        reservation=reservation,
        authorization=authorization,
        attempts=attempts,
        unknown_authorization_ids=unknown,
        history=history,
        snapshot=snapshot,
        visible_after_observation_sequence=account_observation_watermark(
            connection,
            _require_text(row["account_id"], "reservation account ID", maximum=64),
        ),
    )


def verify_reservation_correction_integrity(
    connection: Connection,
    reservation_id: str,
) -> None:
    """Authenticate durable correction evidence without duplicating full head readiness."""

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
        raise ReservationLifecyclePersistenceError(
            "reservation lifecycle integrity references a missing reservation"
        )
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
            "reservation lifecycle integrity lacks its approved decision"
        )
    attempts = _parent_attempts(
        connection,
        decision.decision_id,
        lock=False,
    )
    history = _release_history(connection, decision.reservation)
    correction_material = _correction_freeze_material(connection, attempts, history)
    if correction_material and _persisted_state(row) not in {
        ReservationCapacityState.FROZEN,
        ReservationCapacityState.RELEASED,
    }:
        raise ReservationLifecyclePersistenceError(
            "reservation head is not quarantined by its durable correction history"
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
    correction_material: tuple[tuple[object, ...], ...],
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
    return _snapshot_from_head(row, projection, frozenset(), correction_material)


def _insert_release(
    connection: Connection,
    lifecycle: _LockedLifecycle,
    fact: ReservationReleaseFact,
) -> SqlReservationReleaseResult:
    if lifecycle.history and fact.recorded_at < lifecycle.history[-1].recorded_at:
        raise ReservationLifecyclePersistenceError(
            "new release cannot regress its reservation release chronology"
        )
    account_id = _require_text(
        lifecycle.reservation_row["account_id"],
        "reservation account ID",
        maximum=64,
    )
    decision_rows = tuple(
        connection.execute(
            sa.select(
                phase2_batch_decisions.c.account_observation_sequence,
            )
            .where(phase2_batch_decisions.c.account_id == account_id)
            .order_by(phase2_batch_decisions.c.account_observation_sequence)
        ).mappings()
    )
    decision_sequences = tuple(
        _require_int(row["account_observation_sequence"], "account observation sequence")
        for row in decision_rows
    )
    if decision_sequences != tuple(range(1, len(decision_sequences) + 1)):
        raise ReservationLifecyclePersistenceError(
            "account decision observation sequence is not contiguous"
        )
    if lifecycle.visible_after_observation_sequence != len(decision_sequences):
        raise ReservationLifecyclePersistenceError(
            "new release does not bind the current account observation watermark"
        )
    try:
        inserted = insert_or_verify_atomic(
            connection,
            phase2_reservation_release_events,
            {
                **immutable_reservation_release_values(fact),
                **capacity_visibility_values(
                    account_id=account_id,
                    fact_kind=RESERVATION_RELEASE_VISIBILITY_KIND,
                    fact_sha256=fact.semantic_sha256,
                    visible_after_observation_sequence=(
                        lifecycle.visible_after_observation_sequence
                    ),
                ),
            },
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
    correction_material = _correction_freeze_material(
        connection,
        lifecycle.attempts,
        history,
    )
    snapshot = _updated_snapshot(
        connection,
        lifecycle,
        projection,
        correction_material,
    )
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
    horizon_row = (
        connection.execute(
            sa.select(
                phase2_simulation_horizon_facts.c.horizon_id,
                phase2_simulation_horizon_facts.c.horizon_reference,
                phase2_simulation_horizon_facts.c.horizon_source_sha256,
                phase2_simulation_horizon_facts.c.recorded_at,
                phase2_simulation_horizon_facts.c.semantic_sha256,
            ).where(phase2_simulation_horizon_facts.c.horizon_id == horizon.horizon_id)
        )
        .mappings()
        .one_or_none()
    )
    if horizon_row is None:
        raise ReservationLifecyclePersistenceError(
            "simulation horizon release lacks its exact durable horizon row"
        )
    horizon_recorded_at = _require_datetime(
        horizon_row["recorded_at"],
        "simulation horizon recorded_at",
    )
    if (
        horizon_row["horizon_id"] != horizon.horizon_id
        or horizon_row["horizon_reference"] != horizon.horizon_reference
        or horizon_row["horizon_source_sha256"] != horizon.horizon_source_sha256
        or horizon_row["semantic_sha256"] != horizon.semantic_sha256
    ):
        raise ReservationLifecyclePersistenceError(
            "simulation horizon release conflicts with its durable horizon row"
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
        or release.recorded_at != horizon_recorded_at
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
                visible_after_observation_sequence=(lifecycle.visible_after_observation_sequence),
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
                visible_after_observation_sequence=(lifecycle.visible_after_observation_sequence),
            )
            correction_material = _correction_freeze_material(
                connection,
                lifecycle.attempts,
                lifecycle.history,
            )
            if correction_material:
                if _unsafe_correction_accounting_is_complete(
                    connection,
                    lifecycle,
                    persisted_order,
                    execution_event,
                    correction_material,
                ):
                    self._persist_accounting_source(
                        connection,
                        lifecycle,
                        persisted_order,
                        execution_event,
                        accounting_reference=accounting_reference,
                        accounting_source_sha256=accounting_source_sha256,
                        accounted_at=accounted_at,
                    )
                self._freeze_for_correction(connection, lifecycle)
                frozen_error = ReservationLifecycleFrozen(
                    "downward or non-monotone execution correction froze the reservation"
                )
            else:
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
                    predecessor = _execution_predecessor(persisted_order, execution_event)
                    monotone_baseline = (
                        prior_accounted
                        if predecessor is None
                        else cast(Decimal, predecessor.quantity)
                    )
                    if execution_event.quantity <= monotone_baseline:
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
                visible_after_observation_sequence=(lifecycle.visible_after_observation_sequence),
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
        if lifecycle.snapshot.persisted_state in {
            ReservationCapacityState.FROZEN,
            ReservationCapacityState.RELEASED,
        }:
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
