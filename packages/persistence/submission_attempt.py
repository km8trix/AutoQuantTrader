"""Durable, fence-bound broker-submission preparation and lifecycle facts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.batch_risk import BatchRiskDecision, BatchRiskFactConflict
from packages.domain.canonical import (
    canonical_decimal,
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import exact_decimal_sum
from packages.domain.decision import DecisionTrigger, DecisionTriggerKind
from packages.domain.identifiers import canonical_id
from packages.domain.models import OrderIntent, Side, require_utc
from packages.domain.order_reducer import BrokerOrderEventKind
from packages.domain.reservation_lifecycle import (
    ReservationLifecycleError,
    ReservationReleaseFact,
    ReservationReleaseReason,
    project_reservation_capacity,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    SUBMISSION_ATTEMPT_CONTRACT_VERSION,
    BrokerSubmissionRequest,
    CanonicalSubmissionAttempt,
    SubmissionAttemptConflict,
    SubmissionAttemptError,
    SubmissionAttemptEvent,
    SubmissionAttemptPreparation,
    SubmissionAttemptState,
    UnknownSubmissionResolution,
    _abandon_pending_submission,
    _create_event,
    _create_preparation,
    confirm_submission,
    mark_submission_in_flight,
    mark_submission_unknown,
    prepare_submission_attempt,
    reduce_submission_attempt,
)
from packages.domain.submission_attempt import (
    _require_text as _require_submission_text,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
)
from packages.persistence.batch_risk import load_batch_risk_decision
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase2_account_leases,
    phase2_authorization_consumptions,
    phase2_batch_authorizations,
    phase2_batch_reservations,
    phase2_logical_orders,
    phase2_submission_attempt_events,
    phase2_submission_attempts,
)

PHASE2_SUBMISSION_PERSISTENCE_VERSION = "phase2-durable-submission-v2"
RECOVERY_ERROR_CLASS = "RecoveredInterruptedDispatch"
PENDING_RECOVERY_ERROR_CLASS = "RecoveredPreparedWithoutDispatch"


class SubmissionAttemptPersistenceError(SubmissionAttemptConflict):
    """Durable submission facts are missing, corrupt, or conflict."""


class SqlAccountFenceValidator(Protocol):
    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


def _require_text(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} must be non-empty trimmed text"
        )
    return value


def _require_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} must be a lowercase SHA-256 digest"
        )
    return digest


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_int(value: object, field_name: str, *, positive: bool = True) -> int:
    if type(value) is not int or (value <= 0 if positive else value < 0):
        qualifier = "positive" if positive else "non-negative"
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} must be a {qualifier} integer"
        )
    return value


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} must be a datetime")
    result = as_aware_utc(value)
    try:
        require_utc(result, f"persisted {field_name}")
    except ValueError as error:
        raise SubmissionAttemptPersistenceError(str(error)) from error
    return result


def _require_input_datetime(value: datetime, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise SubmissionAttemptError(f"{field_name} must be a datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise SubmissionAttemptError(str(error)) from error
    return value


def _datetime_text(value: datetime) -> str:
    require_utc(value, "canonical datetime")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _decode_datetime_text(value: object, field_name: str) -> datetime:
    raw = _require_text(value, field_name)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        ) from error
    if parsed.tzinfo is None:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    result = parsed.astimezone(UTC)
    if raw != _datetime_text(result):
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    return result


def _decode_decimal_text(value: object, field_name: str) -> Decimal:
    raw = _require_text(value, field_name)
    try:
        result = canonical_persisted_decimal(Decimal(raw), f"persisted {field_name}")
    except (InvalidOperation, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is not an exact database Decimal"
        ) from error
    if raw != canonical_decimal_text(result):
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} is not canonical")
    return result


def _decode_request_decimal_text(value: object, field_name: str) -> Decimal:
    raw = _require_text(value, field_name)
    try:
        result = canonical_decimal(Decimal(raw))
    except (InvalidOperation, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is not a finite exact Decimal"
        ) from error
    if raw != canonical_decimal_text(result):
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} is not canonical")
    return result


def _require_decimal(value: object, field_name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} must be an exact Decimal")
    try:
        return canonical_persisted_decimal(value, f"persisted {field_name}")
    except ValueError as error:
        raise SubmissionAttemptPersistenceError(str(error)) from error


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SubmissionAttemptPersistenceError(
                "persisted submission JSON contains a duplicate object key"
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
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} must be JSON text")
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object_pairs)
    except SubmissionAttemptPersistenceError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} is invalid JSON"
        ) from error
    if raw != _json_text(value):
        raise SubmissionAttemptPersistenceError(f"persisted {field_name} is not canonical JSON")
    return value


def _require_object(
    value: object,
    field_name: str,
    expected_keys: frozenset[str],
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected_keys:
        raise SubmissionAttemptPersistenceError(
            f"persisted {field_name} has an invalid object shape"
        )
    return cast(dict[str, Any], value)


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _fact_payload(kind: str, semantic_sha256: str) -> str:
    return canonical_json_text(
        (
            PHASE2_SUBMISSION_PERSISTENCE_VERSION,
            SUBMISSION_ATTEMPT_CONTRACT_VERSION,
            kind,
            semantic_sha256,
        )
    )


_INTENT_KEYS = frozenset(
    {
        "intent_id",
        "intent_batch_id",
        "target_id",
        "target_sha256",
        "portfolio_snapshot_sha256",
        "strategy_id",
        "strategy_version",
        "strategy_configuration_sha256",
        "decision_trigger",
        "instrument_id",
        "symbol",
        "side",
        "quantity",
        "reference_price",
        "decision_event_id",
        "reference_event_sha256",
        "decision_event_time",
        "created_at",
        "expires_at",
    }
)
_TRIGGER_KEYS = frozenset({"kind", "trigger_id", "trigger_sha256", "as_of"})


def _intent_object(intent: OrderIntent) -> dict[str, object]:
    intent.__post_init__()
    return {
        "created_at": _datetime_text(intent.created_at),
        "decision_event_id": intent.decision_event_id,
        "decision_event_time": _datetime_text(intent.decision_event_time),
        "decision_trigger": {
            "as_of": _datetime_text(intent.decision_trigger.as_of),
            "kind": intent.decision_trigger.kind.value,
            "trigger_id": intent.decision_trigger.trigger_id,
            "trigger_sha256": intent.decision_trigger.trigger_sha256,
        },
        "expires_at": _datetime_text(intent.expires_at),
        "instrument_id": intent.instrument_id,
        "intent_batch_id": intent.intent_batch_id,
        "intent_id": intent.intent_id,
        "portfolio_snapshot_sha256": intent.portfolio_snapshot_sha256,
        "quantity": canonical_decimal_text(intent.quantity),
        "reference_event_sha256": intent.reference_event_sha256,
        "reference_price": canonical_decimal_text(intent.reference_price),
        "side": intent.side.value,
        "strategy_configuration_sha256": intent.strategy_configuration_sha256,
        "strategy_id": intent.strategy_id,
        "strategy_version": intent.strategy_version,
        "symbol": intent.symbol,
        "target_id": intent.target_id,
        "target_sha256": intent.target_sha256,
    }


def _encode_intent(intent: OrderIntent) -> str:
    return _json_text(_intent_object(intent))


def _decode_intent(raw: object) -> OrderIntent:
    item = _require_object(
        _decode_canonical_json(raw, "intent payload"),
        "intent payload",
        _INTENT_KEYS,
    )
    trigger_item = _require_object(
        item["decision_trigger"],
        "intent decision trigger",
        _TRIGGER_KEYS,
    )
    try:
        trigger = DecisionTrigger(
            kind=DecisionTriggerKind(_require_text(trigger_item["kind"], "intent trigger kind")),
            trigger_id=_require_text(trigger_item["trigger_id"], "intent trigger ID"),
            trigger_sha256=_require_sha256(trigger_item["trigger_sha256"], "intent trigger digest"),
            as_of=_decode_datetime_text(trigger_item["as_of"], "intent trigger as_of"),
        )
        intent = OrderIntent(
            intent_id=_require_text(item["intent_id"], "intent ID"),
            intent_batch_id=_require_text(item["intent_batch_id"], "intent batch ID"),
            target_id=_require_text(item["target_id"], "intent target ID"),
            target_sha256=_require_sha256(item["target_sha256"], "intent target digest"),
            portfolio_snapshot_sha256=_require_sha256(
                item["portfolio_snapshot_sha256"], "intent portfolio digest"
            ),
            strategy_id=_require_text(item["strategy_id"], "intent strategy ID"),
            strategy_version=_require_text(item["strategy_version"], "intent strategy version"),
            strategy_configuration_sha256=_require_sha256(
                item["strategy_configuration_sha256"],
                "intent strategy configuration digest",
            ),
            decision_trigger=trigger,
            instrument_id=_require_text(item["instrument_id"], "intent instrument ID"),
            symbol=_require_text(item["symbol"], "intent symbol"),
            side=Side(_require_text(item["side"], "intent side")),
            quantity=_decode_decimal_text(item["quantity"], "intent quantity"),
            reference_price=_decode_decimal_text(item["reference_price"], "intent reference price"),
            decision_event_id=_require_text(item["decision_event_id"], "intent decision event ID"),
            reference_event_sha256=_require_sha256(
                item["reference_event_sha256"], "intent reference event digest"
            ),
            decision_event_time=_decode_datetime_text(
                item["decision_event_time"], "intent decision event time"
            ),
            created_at=_decode_datetime_text(item["created_at"], "intent created_at"),
            expires_at=_decode_datetime_text(item["expires_at"], "intent expires_at"),
        )
    except SubmissionAttemptPersistenceError:
        raise
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError("persisted intent payload is malformed") from error
    if raw != _encode_intent(intent):
        raise SubmissionAttemptPersistenceError("persisted intent payload changed canonical form")
    return intent


def _request_item(key: str, value: object) -> dict[str, object]:
    if value is None:
        return {"key": key, "type": "null", "value": None}
    if type(value) is bool:
        return {"key": key, "type": "bool", "value": value}
    if type(value) is int:
        return {"key": key, "type": "int", "value": str(value)}
    if type(value) is str:
        return {"key": key, "type": "string", "value": value}
    if type(value) is Decimal:
        return {"key": key, "type": "decimal", "value": canonical_decimal_text(value)}
    raise SubmissionAttemptError("broker request contains an unsupported persisted value")


def _encode_request_payload(request: BrokerSubmissionRequest) -> str:
    return _json_text([_request_item(key, value) for key, value in sorted(request.payload.items())])


def _decode_request_payload(raw: object) -> dict[str, object]:
    value = _decode_canonical_json(raw, "broker request payload")
    if type(value) is not list or not value:
        raise SubmissionAttemptPersistenceError(
            "persisted broker request payload must be a non-empty array"
        )
    result: dict[str, object] = {}
    prior_key: str | None = None
    for index, raw_item in enumerate(value):
        item = _require_object(
            raw_item,
            f"broker request item {index}",
            frozenset({"key", "type", "value"}),
        )
        key = _require_text(item["key"], f"broker request item {index} key")
        kind = _require_text(item["type"], f"broker request item {index} type")
        item_value = item["value"]
        if prior_key is not None and key <= prior_key:
            raise SubmissionAttemptPersistenceError(
                "persisted broker request keys are not unique canonical order"
            )
        prior_key = key
        if kind == "null":
            if item_value is not None:
                raise SubmissionAttemptPersistenceError("persisted null request value is malformed")
            decoded: object = None
        elif kind == "bool":
            if type(item_value) is not bool:
                raise SubmissionAttemptPersistenceError("persisted bool request value is malformed")
            decoded = item_value
        elif kind == "int":
            raw_integer = _require_text(item_value, "broker request integer")
            try:
                decoded = int(raw_integer)
            except ValueError as error:
                raise SubmissionAttemptPersistenceError(
                    "persisted broker request integer is malformed"
                ) from error
            if str(decoded) != raw_integer:
                raise SubmissionAttemptPersistenceError(
                    "persisted broker request integer is not canonical"
                )
        elif kind == "string":
            if type(item_value) is not str:
                raise SubmissionAttemptPersistenceError(
                    "persisted string request value is malformed"
                )
            decoded = item_value
        elif kind == "decimal":
            decoded = _decode_request_decimal_text(item_value, "broker request Decimal")
        else:
            raise SubmissionAttemptPersistenceError(
                "persisted broker request value type is unsupported"
            )
        result[key] = decoded
    return result


def _logical_order_semantic_sha256(
    *,
    preparation: SubmissionAttemptPreparation,
    intent: OrderIntent,
    receipt: AccountFenceReceipt,
) -> str:
    return _semantic_sha256(
        (
            PHASE2_SUBMISSION_PERSISTENCE_VERSION,
            "logical_order",
            preparation.order_id,
            preparation.account_id,
            receipt.fence.fencing_generation,
            receipt.lease_sha256,
            receipt.fence.semantic_sha256,
            preparation.parent_decision_id,
            preparation.reservation_id,
            preparation.authorization_id,
            intent.intent_batch_id,
            intent.intent_id,
            preparation.intent_payload_sha256,
            preparation.attempt_id,
            preparation.client_order_id,
            intent.instrument_id,
            intent.symbol,
            intent.side.value,
            intent.quantity,
            preparation.prepared_at,
        )
    )


def _logical_order_semantic_from_row(row: RowMapping, intent: OrderIntent) -> str:
    return _semantic_sha256(
        (
            PHASE2_SUBMISSION_PERSISTENCE_VERSION,
            "logical_order",
            _require_text(row["order_id"], "logical order ID"),
            _require_text(row["account_id"], "logical order account ID"),
            _require_int(row["fencing_generation"], "logical order fencing generation"),
            _require_sha256(row["lease_sha256"], "logical order lease digest"),
            _require_sha256(row["fence_sha256"], "logical order fence digest"),
            _require_text(row["parent_decision_id"], "logical order parent decision ID"),
            _require_text(row["reservation_id"], "logical order reservation ID"),
            _require_text(row["authorization_id"], "logical order authorization ID"),
            intent.intent_batch_id,
            intent.intent_id,
            _require_sha256(row["intent_payload_sha256"], "logical order intent payload digest"),
            _require_text(row["submission_attempt_id"], "logical order first attempt ID"),
            _require_text(row["client_order_id"], "logical order client order ID"),
            intent.instrument_id,
            intent.symbol,
            intent.side.value,
            _require_decimal(row["quantity"], "logical order quantity"),
            _require_datetime(row["submitted_at"], "logical order submitted_at"),
        )
    )


def _logical_order_values(attempt: CanonicalSubmissionAttempt) -> dict[str, object]:
    preparation = attempt.preparation
    intent = preparation.intent
    receipt = preparation.fence_receipt
    semantic_sha256 = _logical_order_semantic_sha256(
        preparation=preparation,
        intent=intent,
        receipt=receipt,
    )
    return {
        "order_id": preparation.order_id,
        "account_id": preparation.account_id,
        "fencing_generation": receipt.fence.fencing_generation,
        "lease_sha256": receipt.lease_sha256,
        "fence_sha256": receipt.fence.semantic_sha256,
        "parent_decision_id": preparation.parent_decision_id,
        "reservation_id": preparation.reservation_id,
        "authorization_id": preparation.authorization_id,
        "intent_batch_id": intent.intent_batch_id,
        "intent_id": intent.intent_id,
        "intent_payload_sha256": preparation.intent_payload_sha256,
        "intent_payload": _encode_intent(intent),
        "submission_attempt_id": preparation.attempt_id,
        "client_order_id": preparation.client_order_id,
        "instrument_id": intent.instrument_id,
        "symbol": intent.symbol,
        "side": intent.side.value,
        "quantity": intent.quantity,
        "submitted_at": preparation.prepared_at,
        "canonical_payload": _fact_payload("logical_order", semantic_sha256),
        "semantic_sha256": semantic_sha256,
    }


def _consumption_values(attempt: CanonicalSubmissionAttempt) -> dict[str, object]:
    preparation = attempt.preparation
    receipt = preparation.fence_receipt
    consumption_id = canonical_id(
        "phase2-authorization-consumption",
        preparation.authorization_id,
        preparation.order_id,
    )
    semantic_sha256 = _semantic_sha256(
        (
            PHASE2_SUBMISSION_PERSISTENCE_VERSION,
            "authorization_consumption",
            consumption_id,
            preparation.authorization_id,
            preparation.order_id,
            preparation.reservation_id,
            preparation.intent.intent_id,
            preparation.intent_payload_sha256,
            preparation.account_id,
            receipt.fence.fencing_generation,
            receipt.lease_sha256,
            receipt.fence.semantic_sha256,
            preparation.prepared_at,
        )
    )
    return {
        "consumption_id": consumption_id,
        "authorization_id": preparation.authorization_id,
        "order_id": preparation.order_id,
        "reservation_id": preparation.reservation_id,
        "intent_id": preparation.intent.intent_id,
        "intent_payload_sha256": preparation.intent_payload_sha256,
        "account_id": preparation.account_id,
        "fencing_generation": receipt.fence.fencing_generation,
        "lease_sha256": receipt.lease_sha256,
        "fence_sha256": receipt.fence.semantic_sha256,
        "consumed_at": preparation.prepared_at,
        "semantic_sha256": semantic_sha256,
    }


def _attempt_values(attempt: CanonicalSubmissionAttempt) -> dict[str, object]:
    preparation = attempt.preparation
    receipt = preparation.fence_receipt
    request = preparation.request
    return {
        "attempt_id": preparation.attempt_id,
        "order_id": preparation.order_id,
        "account_id": preparation.account_id,
        "fencing_generation": receipt.fence.fencing_generation,
        "lease_sha256": receipt.lease_sha256,
        "fence_sha256": receipt.fence.semantic_sha256,
        "parent_decision_id": preparation.parent_decision_id,
        "authorization_id": preparation.authorization_id,
        "reservation_id": preparation.reservation_id,
        "intent_id": preparation.intent.intent_id,
        "intent_payload_sha256": preparation.intent_payload_sha256,
        "risk_decision_sha256": preparation.risk_decision_sha256,
        "authorization_sha256": preparation.authorization_sha256,
        "fence_receipt_sha256": preparation.fence_receipt_sha256,
        "fence_validated_at": receipt.validated_at,
        "fence_valid_until": receipt.valid_until,
        "attempt_number": preparation.attempt_number,
        "client_order_id": preparation.client_order_id,
        "adapter_id": request.adapter_id,
        "adapter_version": request.adapter_version,
        "operation": request.operation,
        "request_sha256": request.semantic_sha256,
        "request_payload": _encode_request_payload(request),
        "created_at": preparation.prepared_at,
        "canonical_payload": _fact_payload("preparation", preparation.semantic_sha256),
        "semantic_sha256": preparation.semantic_sha256,
    }


def _event_values(event: SubmissionAttemptEvent) -> dict[str, object]:
    dispatch_receipt = event.dispatch_fence_receipt
    return {
        "event_id": event.event_id,
        "attempt_id": event.attempt_id,
        "sequence_number": event.sequence_number,
        "state": event.state.value,
        "occurred_at": event.occurred_at,
        "recorded_at": event.recorded_at,
        "previous_event_sha256": event.previous_event_sha256,
        "dispatch_account_id": (
            None if dispatch_receipt is None else dispatch_receipt.fence.account_id
        ),
        "dispatch_fencing_generation": (
            None if dispatch_receipt is None else dispatch_receipt.fence.fencing_generation
        ),
        "dispatch_lease_sha256": (
            None if dispatch_receipt is None else dispatch_receipt.lease_sha256
        ),
        "dispatch_fence_sha256": (
            None if dispatch_receipt is None else dispatch_receipt.fence.semantic_sha256
        ),
        "dispatch_fence_receipt_sha256": (
            None if dispatch_receipt is None else dispatch_receipt.semantic_sha256
        ),
        "dispatch_fence_validated_at": (
            None if dispatch_receipt is None else dispatch_receipt.validated_at
        ),
        "dispatch_fence_valid_until": (
            None if dispatch_receipt is None else dispatch_receipt.valid_until
        ),
        "response_sha256": event.response_sha256,
        "broker_order_id": event.broker_order_id,
        "error_class": event.error_class,
        "resolution": None if event.resolution is None else event.resolution.value,
        "reconciliation_sha256": event.reconciliation_sha256,
        "canonical_payload": _fact_payload("event", event.semantic_sha256),
        "semantic_sha256": event.semantic_sha256,
    }


def _select_for_update(statement: Any, connection: Connection) -> Any:
    return statement.with_for_update() if connection.dialect.name == "postgresql" else statement


def _locked_reservation(
    connection: Connection,
    reservation_id: str,
    parent_decision_id: str,
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
    if row is None or row["parent_decision_id"] != parent_decision_id:
        raise SubmissionAttemptPersistenceError(
            "submission references a missing or conflicting parent reservation"
        )
    return row


def _authenticate_current_receipt(
    connection: Connection,
    receipt: AccountFenceReceipt,
) -> None:
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == receipt.fence.account_id,
                phase2_account_leases.c.fencing_generation == receipt.fence.fencing_generation,
                phase2_account_leases.c.lease_sha256 == receipt.lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise SubmissionAttemptPersistenceError(
            "SQL fence receipt references a missing immutable lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "SQL fence receipt lease evidence is malformed"
        ) from error
    if (
        receipt.fence != lease.fence
        or receipt.policy_sha256 != lease.policy_sha256
        or receipt.lease_sha256 != lease.semantic_sha256
        or receipt.valid_until != lease.expires_at
        or receipt.validated_at < lease.heartbeat_at
    ):
        raise SubmissionAttemptPersistenceError(
            "SQL fence receipt conflicts with its immutable lease"
        )


def _lease_receipt_from_attempt_row(
    connection: Connection,
    row: RowMapping,
) -> AccountFenceReceipt:
    account_id = _require_text(row["account_id"], "attempt account ID")
    generation = _require_int(row["fencing_generation"], "attempt fencing generation")
    lease_sha256 = _require_sha256(row["lease_sha256"], "attempt lease digest")
    fence_sha256 = _require_sha256(row["fence_sha256"], "attempt fence digest")
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == account_id,
                phase2_account_leases.c.fencing_generation == generation,
                phase2_account_leases.c.lease_sha256 == lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise SubmissionAttemptPersistenceError(
            "persisted submission attempt references a missing lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission lease evidence is malformed"
        ) from error
    validated_at = _require_datetime(row["fence_validated_at"], "fence validated_at")
    valid_until = _require_datetime(row["fence_valid_until"], "fence valid_until")
    if (
        lease.fence.semantic_sha256 != fence_sha256
        or lease.expires_at != valid_until
        or validated_at < lease.heartbeat_at
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted submission fence receipt conflicts with its immutable lease"
        )
    try:
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=validated_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission fence receipt is malformed"
        ) from error
    if row["fence_receipt_sha256"] != receipt.semantic_sha256:
        raise SubmissionAttemptPersistenceError(
            "persisted submission fence receipt digest is inconsistent"
        )
    return receipt


def _logical_order_and_intent(
    connection: Connection,
    attempt_row: RowMapping,
) -> tuple[RowMapping, OrderIntent]:
    order_id = _require_text(attempt_row["order_id"], "attempt order ID")
    row = (
        connection.execute(
            sa.select(phase2_logical_orders).where(phase2_logical_orders.c.order_id == order_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise SubmissionAttemptPersistenceError(
            "persisted submission attempt references a missing logical order"
        )
    intent = _decode_intent(row["intent_payload"])
    if (
        row["intent_id"] != intent.intent_id
        or row["intent_batch_id"] != intent.intent_batch_id
        or row["intent_payload_sha256"] != intent_payload_hash(intent)
        or row["instrument_id"] != intent.instrument_id
        or row["symbol"] != intent.symbol
        or row["side"] != intent.side.value
        or _require_decimal(row["quantity"], "logical order quantity") != intent.quantity
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted logical order conflicts with its exact intent payload"
        )
    for field_name in (
        "order_id",
        "account_id",
        "parent_decision_id",
        "reservation_id",
        "authorization_id",
        "intent_id",
        "intent_payload_sha256",
        "client_order_id",
    ):
        if row[field_name] != attempt_row[field_name]:
            raise SubmissionAttemptPersistenceError(
                "persisted logical order conflicts with its submission attempt"
            )
    first_attempt_row = (
        connection.execute(
            sa.select(phase2_submission_attempts)
            .where(phase2_submission_attempts.c.order_id == order_id)
            .order_by(phase2_submission_attempts.c.attempt_number)
            .limit(1)
        )
        .mappings()
        .one_or_none()
    )
    if first_attempt_row is None or row["submission_attempt_id"] != first_attempt_row["attempt_id"]:
        raise SubmissionAttemptPersistenceError(
            "persisted logical order does not bind its first submission attempt"
        )
    if _require_int(first_attempt_row["attempt_number"], "first submission attempt number") != 1:
        raise SubmissionAttemptPersistenceError(
            "persisted logical order attempt sequence does not begin at one"
        )
    for field_name in (
        "order_id",
        "account_id",
        "fencing_generation",
        "lease_sha256",
        "fence_sha256",
        "parent_decision_id",
        "reservation_id",
        "authorization_id",
        "intent_id",
        "intent_payload_sha256",
        "client_order_id",
    ):
        if first_attempt_row[field_name] != row[field_name]:
            raise SubmissionAttemptPersistenceError(
                "persisted logical order conflicts with its first submission attempt"
            )
    if _require_datetime(
        first_attempt_row["created_at"], "first submission prepared_at"
    ) != _require_datetime(row["submitted_at"], "logical order submitted_at"):
        raise SubmissionAttemptPersistenceError(
            "persisted logical order time conflicts with its first submission attempt"
        )
    authorization = (
        connection.execute(
            sa.select(phase2_batch_authorizations).where(
                phase2_batch_authorizations.c.authorization_id == row["authorization_id"]
            )
        )
        .mappings()
        .one_or_none()
    )
    if authorization is None:
        raise SubmissionAttemptPersistenceError(
            "persisted logical order references a missing authorization"
        )
    authorization_bindings = {
        "authorization_id": "authorization_id",
        "parent_decision_id": "parent_decision_id",
        "reservation_id": "reservation_id",
        "intent_batch_id": "intent_batch_id",
        "intent_id": "intent_id",
        "intent_payload_sha256": "intent_payload_sha256",
        "account_id": "account_id",
        "fencing_generation": "fencing_generation",
        "fence_sha256": "fence_sha256",
        "instrument_id": "instrument_id",
        "symbol": "symbol",
        "side": "side",
        "quantity": "quantity",
    }
    if any(
        authorization[authorization_name] != row[order_name]
        for order_name, authorization_name in authorization_bindings.items()
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted logical order conflicts with its exact authorization"
        )
    semantic_sha256 = _logical_order_semantic_from_row(row, intent)
    if row["semantic_sha256"] != semantic_sha256 or row["canonical_payload"] != _fact_payload(
        "logical_order", semantic_sha256
    ):
        raise SubmissionAttemptPersistenceError("persisted logical order digest is inconsistent")
    consumption = (
        connection.execute(
            sa.select(phase2_authorization_consumptions).where(
                phase2_authorization_consumptions.c.authorization_id == row["authorization_id"]
            )
        )
        .mappings()
        .one_or_none()
    )
    if consumption is None:
        raise SubmissionAttemptPersistenceError(
            "persisted logical order lacks authorization consumption"
        )
    for field_name in (
        "authorization_id",
        "order_id",
        "reservation_id",
        "intent_id",
        "intent_payload_sha256",
        "account_id",
        "fencing_generation",
        "lease_sha256",
        "fence_sha256",
    ):
        if consumption[field_name] != row[field_name]:
            raise SubmissionAttemptPersistenceError(
                "persisted authorization consumption conflicts with its logical order"
            )
    if _require_datetime(consumption["consumed_at"], "authorization consumed_at") != (
        _require_datetime(row["submitted_at"], "logical order submitted_at")
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted authorization consumption time conflicts with preparation"
        )
    expected_consumption = _consumption_values_from_rows(row, consumption)
    if (
        consumption["consumption_id"] != expected_consumption["consumption_id"]
        or consumption["semantic_sha256"] != expected_consumption["semantic_sha256"]
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted authorization consumption digest is inconsistent"
        )
    return row, intent


def _consumption_values_from_rows(
    order_row: RowMapping,
    consumption_row: RowMapping,
) -> dict[str, object]:
    consumption_id = canonical_id(
        "phase2-authorization-consumption",
        order_row["authorization_id"],
        order_row["order_id"],
    )
    consumed_at = _require_datetime(consumption_row["consumed_at"], "consumed_at")
    semantic_sha256 = _semantic_sha256(
        (
            PHASE2_SUBMISSION_PERSISTENCE_VERSION,
            "authorization_consumption",
            consumption_id,
            order_row["authorization_id"],
            order_row["order_id"],
            order_row["reservation_id"],
            order_row["intent_id"],
            order_row["intent_payload_sha256"],
            order_row["account_id"],
            order_row["fencing_generation"],
            order_row["lease_sha256"],
            order_row["fence_sha256"],
            consumed_at,
        )
    )
    return {"consumption_id": consumption_id, "semantic_sha256": semantic_sha256}


def _dispatch_receipt_from_event_row(
    connection: Connection,
    row: RowMapping,
) -> AccountFenceReceipt | None:
    field_names = (
        "dispatch_account_id",
        "dispatch_fencing_generation",
        "dispatch_lease_sha256",
        "dispatch_fence_sha256",
        "dispatch_fence_receipt_sha256",
        "dispatch_fence_validated_at",
        "dispatch_fence_valid_until",
    )
    values = tuple(row[field_name] for field_name in field_names)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch fence receipt is only partially present"
        )
    account_id = _require_text(row["dispatch_account_id"], "dispatch account ID")
    generation = _require_int(
        row["dispatch_fencing_generation"],
        "dispatch fencing generation",
    )
    lease_sha256 = _require_sha256(row["dispatch_lease_sha256"], "dispatch lease digest")
    fence_sha256 = _require_sha256(row["dispatch_fence_sha256"], "dispatch fence digest")
    receipt_sha256 = _require_sha256(
        row["dispatch_fence_receipt_sha256"],
        "dispatch fence receipt digest",
    )
    lease_row = (
        connection.execute(
            sa.select(phase2_account_leases).where(
                phase2_account_leases.c.account_id == account_id,
                phase2_account_leases.c.fencing_generation == generation,
                phase2_account_leases.c.lease_sha256 == lease_sha256,
            )
        )
        .mappings()
        .one_or_none()
    )
    if lease_row is None:
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch receipt references a missing immutable lease"
        )
    try:
        lease = account_lease_from_row(lease_row)
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch receipt lease evidence is malformed"
        ) from error
    validated_at = _require_datetime(
        row["dispatch_fence_validated_at"],
        "dispatch fence validated_at",
    )
    valid_until = _require_datetime(
        row["dispatch_fence_valid_until"],
        "dispatch fence valid_until",
    )
    if (
        lease.fence.semantic_sha256 != fence_sha256
        or lease.expires_at != valid_until
        or validated_at < lease.heartbeat_at
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch fence receipt conflicts with its immutable lease"
        )
    try:
        receipt = _account_fence_receipt(
            fence=lease.fence,
            validated_at=validated_at,
            valid_until=valid_until,
            policy_sha256=lease.policy_sha256,
            lease_sha256=lease.semantic_sha256,
        )
    except (TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch fence receipt is malformed"
        ) from error
    if receipt.semantic_sha256 != receipt_sha256:
        raise SubmissionAttemptPersistenceError(
            "persisted dispatch fence receipt digest is inconsistent"
        )
    return receipt


def _event_from_row(
    connection: Connection,
    row: RowMapping,
) -> SubmissionAttemptEvent:
    try:
        state = SubmissionAttemptState(_require_text(row["state"], "submission event state"))
        resolution_raw = _require_optional_text(row["resolution"], "unknown submission resolution")
        event = _create_event(
            attempt_id=_require_text(row["attempt_id"], "submission event attempt ID"),
            sequence_number=_require_int(row["sequence_number"], "submission event sequence"),
            state=state,
            occurred_at=_require_datetime(row["occurred_at"], "submission event occurred_at"),
            recorded_at=_require_datetime(row["recorded_at"], "submission event recorded_at"),
            previous_event_sha256=_require_optional_sha256(
                row["previous_event_sha256"], "previous submission event digest"
            ),
            dispatch_fence_receipt=_dispatch_receipt_from_event_row(connection, row),
            response_sha256=_require_optional_sha256(
                row["response_sha256"], "broker response digest"
            ),
            broker_order_id=_require_optional_text(row["broker_order_id"], "broker order ID"),
            error_class=_require_optional_text(row["error_class"], "submission error class"),
            resolution=(
                None if resolution_raw is None else UnknownSubmissionResolution(resolution_raw)
            ),
            reconciliation_sha256=_require_optional_sha256(
                row["reconciliation_sha256"], "reconciliation digest"
            ),
        )
    except SubmissionAttemptPersistenceError:
        raise
    except (SubmissionAttemptError, TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission event is malformed"
        ) from error
    if (
        row["event_id"] != event.event_id
        or row["semantic_sha256"] != event.semantic_sha256
        or row["canonical_payload"] != _fact_payload("event", event.semantic_sha256)
    ):
        raise SubmissionAttemptPersistenceError("persisted submission event digest is inconsistent")
    return event


def _attempt_from_row(
    connection: Connection,
    row: RowMapping,
) -> CanonicalSubmissionAttempt:
    decision_id = _require_text(row["parent_decision_id"], "attempt parent decision ID")
    try:
        decision = load_batch_risk_decision(connection, decision_id)
    except BatchRiskFactConflict as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission risk decision is malformed"
        ) from error
    if decision is None:
        raise SubmissionAttemptPersistenceError(
            "persisted submission attempt references a missing risk decision"
        )
    order_row, intent = _logical_order_and_intent(connection, row)
    receipt = _lease_receipt_from_attempt_row(connection, row)
    request_payload = _decode_request_payload(row["request_payload"])
    try:
        request = BrokerSubmissionRequest(
            adapter_id=_require_text(row["adapter_id"], "broker adapter ID"),
            adapter_version=_require_text(row["adapter_version"], "broker adapter version"),
            operation=_require_text(row["operation"], "broker operation"),
            order_id=_require_text(row["order_id"], "broker request order ID"),
            client_order_id=_require_text(row["client_order_id"], "broker request client order ID"),
            intent_payload_sha256=_require_sha256(
                row["intent_payload_sha256"], "broker request intent digest"
            ),
            payload=request_payload,
        )
        preparation = _create_preparation(
            intent=intent,
            risk_decision=decision,
            fence_receipt=receipt,
            request=request,
            attempt_number=_require_int(row["attempt_number"], "submission attempt number"),
            prepared_at=_require_datetime(row["created_at"], "submission prepared_at"),
        )
    except SubmissionAttemptPersistenceError:
        raise
    except (SubmissionAttemptError, TypeError, ValueError) as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission preparation is malformed"
        ) from error
    authorization = next(
        (
            item
            for item in decision.authorizations
            if item.decision_id == preparation.authorization_id
        ),
        None,
    )
    if authorization is None:
        raise SubmissionAttemptPersistenceError(
            "persisted submission authorization is missing from its decision"
        )
    checks = {
        "attempt_id": preparation.attempt_id,
        "order_id": preparation.order_id,
        "account_id": preparation.account_id,
        "parent_decision_id": preparation.parent_decision_id,
        "authorization_id": preparation.authorization_id,
        "reservation_id": preparation.reservation_id,
        "intent_id": preparation.intent.intent_id,
        "intent_payload_sha256": preparation.intent_payload_sha256,
        "risk_decision_sha256": preparation.risk_decision_sha256,
        "authorization_sha256": preparation.authorization_sha256,
        "fence_receipt_sha256": preparation.fence_receipt_sha256,
        "attempt_number": preparation.attempt_number,
        "client_order_id": preparation.client_order_id,
        "request_sha256": preparation.request.semantic_sha256,
        "semantic_sha256": preparation.semantic_sha256,
    }
    if any(row[name] != expected for name, expected in checks.items()):
        raise SubmissionAttemptPersistenceError(
            "persisted submission preparation conflicts with its exact evidence"
        )
    if row["request_payload"] != _encode_request_payload(request) or row[
        "canonical_payload"
    ] != _fact_payload("preparation", preparation.semantic_sha256):
        raise SubmissionAttemptPersistenceError(
            "persisted submission preparation payload is inconsistent"
        )
    if (
        order_row["parent_decision_id"] != decision.decision_id
        or order_row["authorization_id"] != authorization.decision_id
    ):
        raise SubmissionAttemptPersistenceError(
            "persisted logical order conflicts with its risk authorization"
        )
    events = tuple(
        _event_from_row(connection, event_row)
        for event_row in connection.execute(
            sa.select(phase2_submission_attempt_events)
            .where(phase2_submission_attempt_events.c.attempt_id == preparation.attempt_id)
            .order_by(phase2_submission_attempt_events.c.sequence_number)
        )
        .mappings()
        .all()
    )
    try:
        return reduce_submission_attempt(preparation, events)
    except SubmissionAttemptError as error:
        raise SubmissionAttemptPersistenceError(
            "persisted submission event history is not canonical"
        ) from error


def load_submission_attempt(
    connection: Connection,
    attempt_id: str,
) -> CanonicalSubmissionAttempt | None:
    """Strictly reconstruct one durable preparation and its complete event chain."""

    row = (
        connection.execute(
            sa.select(phase2_submission_attempts).where(
                phase2_submission_attempts.c.attempt_id == attempt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _attempt_from_row(connection, row)


def _parent_attempts(
    connection: Connection,
    parent_decision_id: str,
    *,
    lock: bool,
) -> tuple[CanonicalSubmissionAttempt, ...]:
    statement = (
        sa.select(phase2_submission_attempts)
        .where(phase2_submission_attempts.c.parent_decision_id == parent_decision_id)
        .order_by(
            phase2_submission_attempts.c.order_id,
            phase2_submission_attempts.c.attempt_number,
            phase2_submission_attempts.c.attempt_id,
        )
    )
    rows = tuple(
        connection.execute(_select_for_update(statement, connection) if lock else statement)
        .mappings()
        .all()
    )
    return tuple(_attempt_from_row(connection, row) for row in rows)


def _unknown_attempt_ids(attempts: tuple[CanonicalSubmissionAttempt, ...]) -> tuple[str, ...]:
    return tuple(
        attempt.attempt_id
        for attempt in attempts
        if attempt.state is SubmissionAttemptState.UNKNOWN
    )


_CORRECTION_CLOSURE_REASONS = frozenset(
    {
        ReservationReleaseReason.RECONCILED_TERMINAL,
        ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
    }
)


def _strict_reservation_release_history(
    connection: Connection,
    reservation_id: str,
) -> tuple[ReservationReleaseFact, ...]:
    # Imported lazily because the lifecycle repository uses this module's strict
    # submission loader while reconstructing its own immutable evidence.
    from packages.persistence.reservation_lifecycle import (
        load_reservation_release_history,
    )

    try:
        return load_reservation_release_history(connection, reservation_id)
    except ReservationLifecycleError as error:
        raise SubmissionAttemptPersistenceError(
            "reservation freeze references malformed lifecycle evidence"
        ) from error


def _require_remaining_authorization_capacity(
    connection: Connection,
    decision: BatchRiskDecision,
    authorization_id: str,
) -> None:
    reservation = decision.reservation
    if reservation is None:
        raise SubmissionAttemptPersistenceError("submission requires an approved reservation")
    try:
        projection = project_reservation_capacity(
            reservation,
            _strict_reservation_release_history(
                connection,
                reservation.reservation_id,
            ),
        )
    except ReservationLifecycleError as error:
        raise SubmissionAttemptPersistenceError(
            "submission reservation release history is not canonical"
        ) from error
    matches = tuple(
        child for child in projection.authorizations if child.authorization_id == authorization_id
    )
    if len(matches) != 1:
        raise SubmissionAttemptPersistenceError(
            "submission authorization is missing from its reservation projection"
        )
    if matches[0].fully_released:
        raise SubmissionAttemptPersistenceError(
            "submission authorization capacity is already fully released"
        )


def _has_unresolved_nonmonotone_correction(
    connection: Connection,
    reservation_row: RowMapping,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> bool:
    from packages.persistence.reservation_lifecycle import load_canonical_order_state

    reservation_id = _require_text(
        reservation_row["reservation_id"],
        "reservation ID",
    )
    history = _strict_reservation_release_history(connection, reservation_id)
    latest_by_authorization: dict[str, CanonicalSubmissionAttempt] = {}
    for attempt in attempts:
        latest_by_authorization[attempt.preparation.authorization_id] = attempt
    for attempt in latest_by_authorization.values():
        try:
            order_state = load_canonical_order_state(connection, attempt.attempt_id)
        except ReservationLifecycleError as error:
            raise SubmissionAttemptPersistenceError(
                "reservation freeze references malformed order evidence"
            ) from error
        if order_state is None:
            raise SubmissionAttemptPersistenceError(
                "reservation freeze references a missing durable order"
            )
        for execution in order_state.executions:
            matches = tuple(
                event for event in order_state.broker_events if event.event_id == execution.event_id
            )
            if len(matches) != 1:
                raise SubmissionAttemptPersistenceError(
                    "canonical execution head lacks its exact broker event"
                )
            event = matches[0]
            if event.kind is not BrokerOrderEventKind.EXECUTION_CORRECTION:
                continue
            exact_accounting = tuple(
                fact
                for fact in history
                if fact.authorization_id == attempt.preparation.authorization_id
                and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
                and fact.order_event_id == event.event_id
            )
            if exact_accounting:
                continue
            prior_accounted = exact_decimal_sum(
                fact.accounted_quantity
                for fact in history
                if fact.authorization_id == attempt.preparation.authorization_id
                and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
                and fact.execution_id == execution.execution_id
                and fact.accounted_quantity is not None
            )
            closed = any(
                fact.authorization_id == attempt.preparation.authorization_id
                and fact.attempt_id == attempt.attempt_id
                and fact.order_id == order_state.submission.order_id
                and fact.reason in _CORRECTION_CLOSURE_REASONS
                and fact.occurred_at >= execution.received_at
                for fact in history
            )
            if not closed and execution.quantity <= prior_accounted:
                return True
    return False


def _assert_freeze_consistency(
    connection: Connection,
    reservation_row: RowMapping,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> bool:
    unknown = _unknown_attempt_ids(attempts)
    state = _require_text(reservation_row["state"], "reservation state")
    if unknown and state != "frozen":
        raise SubmissionAttemptPersistenceError(
            "persisted parent reservation freeze disagrees with UNKNOWN attempts"
        )
    correction_frozen = state == "frozen" and _has_unresolved_nonmonotone_correction(
        connection,
        reservation_row,
        attempts,
    )
    if state == "frozen" and not unknown and not correction_frozen:
        raise SubmissionAttemptPersistenceError(
            "frozen reservation lacks UNKNOWN or non-monotone correction evidence"
        )
    return correction_frozen


def _locked_parent_for_attempt(
    connection: Connection,
    attempt_id: str,
) -> tuple[
    RowMapping,
    tuple[CanonicalSubmissionAttempt, ...],
    CanonicalSubmissionAttempt,
    bool,
]:
    location = (
        connection.execute(
            sa.select(
                phase2_submission_attempts.c.reservation_id,
                phase2_submission_attempts.c.parent_decision_id,
            ).where(phase2_submission_attempts.c.attempt_id == attempt_id)
        )
        .mappings()
        .one_or_none()
    )
    if location is None:
        raise SubmissionAttemptPersistenceError("submission attempt does not exist")
    reservation_id = _require_text(location["reservation_id"], "attempt reservation ID")
    parent_decision_id = _require_text(location["parent_decision_id"], "attempt parent decision ID")
    reservation_row = _locked_reservation(
        connection,
        reservation_id,
        parent_decision_id,
    )
    attempts = _parent_attempts(
        connection,
        parent_decision_id,
        lock=True,
    )
    matches = tuple(attempt for attempt in attempts if attempt.attempt_id == attempt_id)
    if len(matches) != 1:
        raise SubmissionAttemptPersistenceError(
            "locked parent snapshot does not contain the requested attempt exactly once"
        )
    correction_frozen = _assert_freeze_consistency(
        connection,
        reservation_row,
        attempts,
    )
    return reservation_row, attempts, matches[0], correction_frozen


def _verify_existing_rows(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
) -> None:
    order_row = (
        connection.execute(
            sa.select(phase2_logical_orders).where(
                phase2_logical_orders.c.order_id == attempt.order_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if order_row is None:
        raise SubmissionAttemptPersistenceError("logical order disappeared during retry")
    intent = _decode_intent(order_row["intent_payload"])
    if intent != attempt.preparation.intent:
        raise SubmissionAttemptPersistenceError("logical order intent is immutable")
    if order_row["client_order_id"] != attempt.preparation.client_order_id:
        raise SubmissionAttemptPersistenceError("logical order client ID is immutable")
    consumption = (
        connection.execute(
            sa.select(phase2_authorization_consumptions).where(
                phase2_authorization_consumptions.c.authorization_id
                == attempt.preparation.authorization_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if consumption is None or consumption["order_id"] != attempt.order_id:
        raise SubmissionAttemptPersistenceError(
            "retry lacks the exact original authorization consumption"
        )


def _initial_envelope_matches_authorization(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
) -> None:
    authorization_row = (
        connection.execute(
            sa.select(phase2_batch_authorizations).where(
                phase2_batch_authorizations.c.authorization_id
                == attempt.preparation.authorization_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if authorization_row is None:
        raise SubmissionAttemptPersistenceError(
            "initial submission references a missing authorization"
        )
    receipt = attempt.preparation.fence_receipt
    expected = (
        receipt.fence.account_id,
        receipt.fence.fencing_generation,
        receipt.fence.semantic_sha256,
    )
    actual = tuple(
        authorization_row[name] for name in ("account_id", "fencing_generation", "fence_sha256")
    )
    if actual != expected:
        raise SubmissionAttemptPersistenceError(
            "initial submission fence must match the authorization stable fence"
        )


def _insert_preparation(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
) -> None:
    try:
        if attempt.attempt_number == 1:
            _initial_envelope_matches_authorization(connection, attempt)
            connection.execute(
                sa.insert(phase2_logical_orders).values(**_logical_order_values(attempt))
            )
            connection.execute(
                sa.insert(phase2_authorization_consumptions).values(**_consumption_values(attempt))
            )
        else:
            _verify_existing_rows(connection, attempt)
        connection.execute(sa.insert(phase2_submission_attempts).values(**_attempt_values(attempt)))
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(**_event_values(attempt.events[0]))
        )
    except IntegrityError as error:
        raise SubmissionAttemptPersistenceError(
            "durable submission preparation conflicts with immutable SQL facts"
        ) from error


class SqlSubmissionAttemptRepository:
    """Persist broker-call preparation before dispatch and append exact outcomes."""

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not isinstance(engine, Engine):
            raise SubmissionAttemptPersistenceError(
                "submission repository requires a SQLAlchemy Engine"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise SubmissionAttemptPersistenceError(
                "submission repository requires a SQL fence validator"
            )
        self._engine = engine
        self._coordinator = coordinator

    def prepare(
        self,
        *,
        intent: OrderIntent,
        risk_decision: BatchRiskDecision,
        fence: AccountFence,
        request: BrokerSubmissionRequest,
        prepared_at: datetime,
        recorded_at: datetime,
    ) -> CanonicalSubmissionAttempt:
        """Atomically consume approval and persist PENDING before any broker call."""

        if type(intent) is not OrderIntent:
            raise SubmissionAttemptError("durable preparation requires an exact OrderIntent")
        if type(risk_decision) is not BatchRiskDecision:
            raise SubmissionAttemptError(
                "durable preparation requires an exact batch risk decision"
            )
        if type(fence) is not AccountFence:
            raise SubmissionAttemptError("durable preparation requires an exact account fence")
        if type(request) is not BrokerSubmissionRequest:
            raise SubmissionAttemptError("durable preparation requires an exact broker request")
        prepared_at = _require_input_datetime(prepared_at, "submission prepared_at")
        recorded_at = _require_input_datetime(recorded_at, "pending event recorded_at")
        with _write_transaction(self._engine) as connection:
            receipt = self._coordinator.revalidate_in_transaction(
                connection,
                fence,
                checked_at=prepared_at,
            )
            if type(receipt) is not AccountFenceReceipt:
                raise SubmissionAttemptPersistenceError(
                    "SQL fence validator returned non-canonical receipt evidence"
                )
            receipt._validate()
            if receipt.fence != fence or receipt.validated_at != prepared_at:
                raise SubmissionAttemptPersistenceError(
                    "SQL fence receipt does not bind the requested fence and instant"
                )
            _authenticate_current_receipt(connection, receipt)
            persisted_decision = load_batch_risk_decision(
                connection,
                risk_decision.decision_id,
            )
            if persisted_decision != risk_decision:
                raise SubmissionAttemptPersistenceError(
                    "submission risk decision differs from its exact durable facts"
                )
            if risk_decision.reservation is None:
                raise SubmissionAttemptError("submission requires an approved reservation")
            reservation_row = _locked_reservation(
                connection,
                risk_decision.reservation.reservation_id,
                risk_decision.decision_id,
            )
            state = _require_text(reservation_row["state"], "reservation state")
            if state == "released":
                raise SubmissionAttemptError("submission reservation is already released")
            parent_attempts = _parent_attempts(
                connection,
                risk_decision.decision_id,
                lock=True,
            )
            correction_frozen = _assert_freeze_consistency(
                connection,
                reservation_row,
                parent_attempts,
            )
            if correction_frozen:
                raise SubmissionAttemptPersistenceError(
                    "non-monotone execution correction freezes new submission preparation"
                )
            authorization = next(
                (
                    item
                    for item in risk_decision.authorizations
                    if item.intent_id == intent.intent_id
                ),
                None,
            )
            if authorization is None:
                raise SubmissionAttemptPersistenceError(
                    "submission intent lacks its exact durable authorization"
                )
            _require_remaining_authorization_capacity(
                connection,
                risk_decision,
                authorization.decision_id,
            )
            attempt = prepare_submission_attempt(
                intent=intent,
                risk_decision=risk_decision,
                fence_receipt=receipt,
                request=request,
                prepared_at=prepared_at,
                recorded_at=recorded_at,
                parent_attempts=parent_attempts,
            )
            _insert_preparation(connection, attempt)
            persisted = load_submission_attempt(connection, attempt.attempt_id)
            if persisted != attempt:
                raise SubmissionAttemptPersistenceError(
                    "SQL storage did not preserve the exact submission preparation"
                )
            return attempt

    def get(self, attempt_id: str) -> CanonicalSubmissionAttempt | None:
        with self._engine.connect() as connection:
            attempt = load_submission_attempt(connection, attempt_id)
            if attempt is None:
                return None
            reservation_row = _locked_reservation(
                connection,
                attempt.preparation.reservation_id,
                attempt.parent_decision_id,
            )
            attempts = _parent_attempts(
                connection,
                attempt.parent_decision_id,
                lock=False,
            )
            _assert_freeze_consistency(connection, reservation_row, attempts)
            return attempt

    def for_parent(
        self,
        parent_decision_id: str,
    ) -> tuple[CanonicalSubmissionAttempt, ...]:
        with self._engine.connect() as connection:
            attempts = _parent_attempts(connection, parent_decision_id, lock=False)
            if attempts:
                reservation_row = _locked_reservation(
                    connection,
                    attempts[0].preparation.reservation_id,
                    parent_decision_id,
                )
                _assert_freeze_consistency(connection, reservation_row, attempts)
            return attempts

    def mark_in_flight(
        self,
        attempt_id: str,
        *,
        fence: AccountFence,
        occurred_at: datetime,
        recorded_at: datetime,
    ) -> CanonicalSubmissionAttempt:
        """Append IN_FLIGHT only while the original stable fence remains current."""

        occurred_at = _require_input_datetime(occurred_at, "dispatch occurred_at")
        recorded_at = _require_input_datetime(recorded_at, "dispatch recorded_at")
        with _write_transaction(self._engine) as connection:
            receipt = self._coordinator.revalidate_in_transaction(
                connection,
                fence,
                checked_at=occurred_at,
            )
            if type(receipt) is not AccountFenceReceipt:
                raise SubmissionAttemptPersistenceError(
                    "SQL fence validator returned non-canonical receipt evidence"
                )
            receipt._validate()
            _authenticate_current_receipt(connection, receipt)
            reservation_row, parent_attempts, current, correction_frozen = (
                _locked_parent_for_attempt(
                    connection,
                    attempt_id,
                )
            )
            if (
                receipt.fence != fence
                or receipt.validated_at != occurred_at
                or fence != current.preparation.fence_receipt.fence
            ):
                raise SubmissionAttemptPersistenceError(
                    "dispatch fence does not match the prepared stable fence"
                )
            if reservation_row["state"] == "released":
                raise SubmissionAttemptError("submission reservation is already released")
            if _unknown_attempt_ids(parent_attempts):
                raise SubmissionAttemptError(
                    "parent batch has an unresolved UNKNOWN submission; dispatch is fenced"
                )
            if correction_frozen:
                raise SubmissionAttemptError(
                    "non-monotone execution correction freezes broker dispatch"
                )
            _require_remaining_authorization_capacity(
                connection,
                current.preparation.risk_decision,
                current.preparation.authorization_id,
            )
            updated = mark_submission_in_flight(
                current,
                dispatch_fence_receipt=receipt,
                occurred_at=occurred_at,
                recorded_at=recorded_at,
            )
            return self._append(connection, updated)

    def confirm(
        self,
        attempt_id: str,
        *,
        occurred_at: datetime,
        recorded_at: datetime,
        response_sha256: str,
        broker_order_id: str,
    ) -> CanonicalSubmissionAttempt:
        """Record a broker success without revalidating a possibly expired fence."""

        return self._append_outcome(
            attempt_id,
            lambda current: confirm_submission(
                current,
                occurred_at=_require_input_datetime(occurred_at, "confirmation occurred_at"),
                recorded_at=_require_input_datetime(recorded_at, "confirmation recorded_at"),
                response_sha256=response_sha256,
                broker_order_id=broker_order_id,
            ),
        )

    def mark_unknown(
        self,
        attempt_id: str,
        *,
        occurred_at: datetime,
        recorded_at: datetime,
        error_class: str,
    ) -> CanonicalSubmissionAttempt:
        """Record uncertainty and atomically freeze the complete parent reservation."""

        return self._append_outcome(
            attempt_id,
            lambda current: mark_submission_unknown(
                current,
                occurred_at=_require_input_datetime(occurred_at, "unknown occurred_at"),
                recorded_at=_require_input_datetime(recorded_at, "unknown recorded_at"),
                error_class=error_class,
            ),
            freeze=True,
        )

    def resolve_unknown(
        self,
        attempt_id: str,
        *,
        occurred_at: datetime,
        recorded_at: datetime,
        resolution: UnknownSubmissionResolution,
        reconciliation_sha256: str,
        response_sha256: str | None = None,
        broker_order_id: str | None = None,
    ) -> CanonicalSubmissionAttempt:
        """Fail closed until durable authenticated broker reconciliation exists."""

        raise SubmissionAttemptPersistenceError(
            "UNKNOWN submission resolution requires a durable authenticated broker "
            "reconciliation evidence producer"
        )

    def recover_stale_pending(
        self,
        *,
        stale_before: datetime,
        recovered_at: datetime,
        recorded_at: datetime,
        error_class: str = PENDING_RECOVERY_ERROR_CLASS,
    ) -> tuple[CanonicalSubmissionAttempt, ...]:
        """Append proven-unsent abandonment to stale PENDING heads under SQL locks."""

        stale_before = _require_input_datetime(stale_before, "pending recovery stale_before")
        recovered_at = _require_input_datetime(recovered_at, "pending recovered_at")
        recorded_at = _require_input_datetime(recorded_at, "pending recovery recorded_at")
        _require_submission_text(error_class, "pending recovery error class")
        if recovered_at < stale_before:
            raise SubmissionAttemptError("pending recovery cannot occur before its stale cutoff")
        if recorded_at < recovered_at:
            raise SubmissionAttemptError("pending recovery cannot be recorded before it occurred")
        recovered: list[CanonicalSubmissionAttempt] = []
        with _write_transaction(self._engine) as connection:
            head = (
                sa.select(
                    phase2_submission_attempt_events.c.attempt_id,
                    sa.func.max(phase2_submission_attempt_events.c.sequence_number).label(
                        "sequence_number"
                    ),
                )
                .group_by(phase2_submission_attempt_events.c.attempt_id)
                .subquery()
            )
            candidate_ids = tuple(
                _require_text(row[0], "stale pending attempt ID")
                for row in connection.execute(
                    sa.select(phase2_submission_attempt_events.c.attempt_id)
                    .join(
                        head,
                        sa.and_(
                            head.c.attempt_id == phase2_submission_attempt_events.c.attempt_id,
                            head.c.sequence_number
                            == phase2_submission_attempt_events.c.sequence_number,
                        ),
                    )
                    .where(
                        phase2_submission_attempt_events.c.state == "pending",
                        phase2_submission_attempt_events.c.recorded_at < stale_before,
                    )
                    .order_by(phase2_submission_attempt_events.c.attempt_id)
                )
            )
            for attempt_id in candidate_ids:
                reservation_row, _, current, _correction_frozen = _locked_parent_for_attempt(
                    connection,
                    attempt_id,
                )
                if current.state is not SubmissionAttemptState.PENDING:
                    continue
                if current.events[-1].recorded_at >= stale_before:
                    continue
                if reservation_row["state"] == "released":
                    raise SubmissionAttemptPersistenceError(
                        "cannot abandon pending submission after reservation release"
                    )
                updated = _abandon_pending_submission(
                    current,
                    occurred_at=recovered_at,
                    recorded_at=recorded_at,
                    error_class=error_class,
                )
                persisted = self._append(connection, updated)
                recovered.append(persisted)
                attempts = _parent_attempts(
                    connection,
                    current.parent_decision_id,
                    lock=True,
                )
                refreshed_reservation = _locked_reservation(
                    connection,
                    current.preparation.reservation_id,
                    current.parent_decision_id,
                )
                _assert_freeze_consistency(
                    connection,
                    refreshed_reservation,
                    attempts,
                )
        return tuple(recovered)

    def recover_stale_in_flight(
        self,
        *,
        stale_before: datetime,
        recovered_at: datetime,
        recorded_at: datetime,
        error_class: str = RECOVERY_ERROR_CLASS,
    ) -> tuple[CanonicalSubmissionAttempt, ...]:
        """Promote every still-IN_FLIGHT head older than the cutoff to UNKNOWN."""

        stale_before = _require_input_datetime(stale_before, "recovery stale_before")
        recovered_at = _require_input_datetime(recovered_at, "recovery recovered_at")
        recorded_at = _require_input_datetime(recorded_at, "recovery recorded_at")
        recovered: list[CanonicalSubmissionAttempt] = []
        with _write_transaction(self._engine) as connection:
            head = (
                sa.select(
                    phase2_submission_attempt_events.c.attempt_id,
                    sa.func.max(phase2_submission_attempt_events.c.sequence_number).label(
                        "sequence_number"
                    ),
                )
                .group_by(phase2_submission_attempt_events.c.attempt_id)
                .subquery()
            )
            candidate_ids = tuple(
                row[0]
                for row in connection.execute(
                    sa.select(phase2_submission_attempt_events.c.attempt_id)
                    .join(
                        head,
                        sa.and_(
                            head.c.attempt_id == phase2_submission_attempt_events.c.attempt_id,
                            head.c.sequence_number
                            == phase2_submission_attempt_events.c.sequence_number,
                        ),
                    )
                    .where(
                        phase2_submission_attempt_events.c.state == "in_flight",
                        phase2_submission_attempt_events.c.recorded_at < stale_before,
                    )
                    .order_by(phase2_submission_attempt_events.c.attempt_id)
                )
            )
            for attempt_id in candidate_ids:
                reservation_row, _, current, _ = _locked_parent_for_attempt(
                    connection,
                    str(attempt_id),
                )
                if current.state is not SubmissionAttemptState.IN_FLIGHT:
                    continue
                if reservation_row["state"] == "released":
                    raise SubmissionAttemptPersistenceError(
                        "cannot recover an in-flight attempt after reservation release"
                    )
                updated = mark_submission_unknown(
                    current,
                    occurred_at=recovered_at,
                    recorded_at=recorded_at,
                    error_class=error_class,
                )
                persisted = self._append(connection, updated)
                if reservation_row["state"] != "frozen":
                    connection.execute(
                        sa.update(phase2_batch_reservations)
                        .where(
                            phase2_batch_reservations.c.reservation_id
                            == current.preparation.reservation_id
                        )
                        .values(
                            state="frozen",
                            state_version=phase2_batch_reservations.c.state_version + 1,
                        )
                    )
                recovered.append(persisted)
                attempts = _parent_attempts(
                    connection,
                    current.parent_decision_id,
                    lock=True,
                )
                refreshed_reservation = _locked_reservation(
                    connection,
                    current.preparation.reservation_id,
                    current.parent_decision_id,
                )
                _assert_freeze_consistency(
                    connection,
                    refreshed_reservation,
                    attempts,
                )
        return tuple(recovered)

    def _append(
        self,
        connection: Connection,
        updated: CanonicalSubmissionAttempt,
    ) -> CanonicalSubmissionAttempt:
        event = updated.events[-1]
        try:
            connection.execute(
                sa.insert(phase2_submission_attempt_events).values(**_event_values(event))
            )
        except IntegrityError as error:
            raise SubmissionAttemptPersistenceError(
                "submission event conflicts with immutable SQL history"
            ) from error
        persisted = load_submission_attempt(connection, updated.attempt_id)
        if persisted != updated:
            raise SubmissionAttemptPersistenceError(
                "SQL storage did not preserve the exact submission event"
            )
        return updated

    def _append_outcome(
        self,
        attempt_id: str,
        transition: Callable[[CanonicalSubmissionAttempt], CanonicalSubmissionAttempt],
        *,
        freeze: bool = False,
    ) -> CanonicalSubmissionAttempt:
        with _write_transaction(self._engine) as connection:
            reservation_row, _, current, _correction_frozen = _locked_parent_for_attempt(
                connection,
                attempt_id,
            )
            if reservation_row["state"] == "released":
                raise SubmissionAttemptPersistenceError(
                    "cannot append submission outcome after reservation release"
                )
            updated = transition(current)
            persisted = self._append(connection, updated)
            if freeze and reservation_row["state"] != "frozen":
                connection.execute(
                    sa.update(phase2_batch_reservations)
                    .where(
                        phase2_batch_reservations.c.reservation_id
                        == current.preparation.reservation_id
                    )
                    .values(
                        state="frozen",
                        state_version=phase2_batch_reservations.c.state_version + 1,
                    )
                )
            attempts = _parent_attempts(
                connection,
                current.parent_decision_id,
                lock=True,
            )
            refreshed_reservation = _locked_reservation(
                connection,
                current.preparation.reservation_id,
                current.parent_decision_id,
            )
            _assert_freeze_consistency(
                connection,
                refreshed_reservation,
                attempts,
            )
            return persisted
