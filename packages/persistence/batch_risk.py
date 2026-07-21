"""Durable, fence-bound issuance of complete Phase 2 batch approvals."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol, TypeVar, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.batch_risk import (
    BATCH_RISK_CONTRACT_VERSION,
    ActiveCapacityAuthorization,
    ActiveCapacityReservation,
    ActiveCapacityReservationState,
    ActiveCapacityUniverse,
    BatchRiskAuthority,
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskError,
    BatchRiskFactConflict,
    BatchRiskReservation,
    VersionedBatchRiskSnapshot,
    evaluate_batch_risk_decision,
)
from packages.domain.canonical import (
    canonical_decimal_text,
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)
from packages.domain.decimal_math import exact_decimal_add, exact_decimal_sum
from packages.domain.identifiers import canonical_id
from packages.domain.models import (
    DecisionStatus,
    OrderIntentBatch,
    RiskRuleResult,
    Side,
    TargetPortfolio,
    require_utc,
)
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    CanonicalOrderState,
    OrderLifecycleError,
    reduce_order_lifecycle,
)
from packages.domain.reservation_lifecycle import (
    ReservationCapacityProjection,
    ReservationCapacityState,
    ReservationLifecycleError,
    ReservationReleaseFact,
    ReservationReleaseReason,
    project_reservation_capacity,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    SubmissionAttemptState,
    reduce_submission_attempt,
)
from packages.persistence.account_coordinator import account_lease_from_row
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase2_account_leases,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_members,
    phase2_batch_reservations,
    phase2_reservation_release_events,
    phase2_submission_attempts,
)

PHASE2_BATCH_RISK_PERSISTENCE_VERSION = "phase2-durable-batch-risk-v3"
SnapshotResultT = TypeVar("SnapshotResultT")


class SqlAccountFenceValidator(Protocol):
    """Narrow coordinator capability used inside a caller-owned transaction."""

    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


class _SnapshotTransactions(Protocol):
    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], SnapshotResultT],
    ) -> SnapshotResultT: ...


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise BatchRiskFactConflict(f"persisted {field_name} must be non-empty trimmed text")
    return value


def _require_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_int(value: object, field_name: str, *, non_negative: bool = False) -> int:
    if type(value) is not int or (value < 0 if non_negative else value <= 0):
        qualifier = "non-negative" if non_negative else "positive"
        raise BatchRiskFactConflict(f"persisted {field_name} must be a {qualifier} integer")
    return value


def _require_decimal(
    value: object,
    field_name: str,
    *,
    positive: bool = False,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise BatchRiskFactConflict(f"persisted {field_name} must be an exact Decimal")
    if value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        raise BatchRiskFactConflict(f"persisted {field_name} must be {qualifier}")
    try:
        return canonical_persisted_decimal(value, f"persisted {field_name}")
    except ValueError as error:
        raise BatchRiskFactConflict(str(error)) from error


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise BatchRiskFactConflict(f"persisted {field_name} must be a datetime")
    instant = as_aware_utc(value)
    try:
        require_utc(instant, f"persisted {field_name}")
    except ValueError as error:
        raise BatchRiskFactConflict(str(error)) from error
    return instant


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BatchRiskFactConflict("persisted JSON contains a duplicate object key")
        result[key] = value
    return result


def _canonical_rules_payload(rules: tuple[RiskRuleResult, ...]) -> str:
    return json.dumps(
        [
            {
                "limit": rule.limit,
                "observed": rule.observed,
                "passed": rule.passed,
                "rule": rule.rule,
            }
            for rule in rules
        ],
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_rules(raw: object) -> tuple[RiskRuleResult, ...]:
    if type(raw) is not str:
        raise BatchRiskFactConflict("persisted batch rules payload must be text")
    try:
        decoded = json.loads(raw, object_pairs_hook=_strict_object_pairs)
    except BatchRiskFactConflict:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise BatchRiskFactConflict("persisted batch rules payload is invalid JSON") from error
    if type(decoded) is not list:
        raise BatchRiskFactConflict("persisted batch rules payload must be an array")
    rules: list[RiskRuleResult] = []
    expected_keys = {"limit", "observed", "passed", "rule"}
    for index, item in enumerate(decoded):
        if type(item) is not dict or set(item) != expected_keys:
            raise BatchRiskFactConflict(f"persisted batch rule {index} has an invalid object shape")
        if type(item["passed"]) is not bool or any(
            type(item[key]) is not str for key in ("limit", "observed", "rule")
        ):
            raise BatchRiskFactConflict(f"persisted batch rule {index} has invalid field types")
        try:
            rules.append(
                RiskRuleResult(
                    rule=item["rule"],
                    passed=item["passed"],
                    observed=item["observed"],
                    limit=item["limit"],
                )
            )
        except ValueError as error:
            raise BatchRiskFactConflict(f"persisted batch rule {index} is invalid") from error
    result = tuple(rules)
    if raw != _canonical_rules_payload(result):
        raise BatchRiskFactConflict("persisted batch rules payload is not canonical JSON")
    return result


def _active_capacity_payload(universe: ActiveCapacityUniverse) -> str:
    if type(universe) is not ActiveCapacityUniverse:
        raise BatchRiskFactConflict("active capacity persistence requires an exact universe")
    universe.__post_init__()
    return json.dumps(
        {
            "account_id": universe.account_id,
            "contract_version": BATCH_RISK_CONTRACT_VERSION,
            "persistence_version": PHASE2_BATCH_RISK_PERSISTENCE_VERSION,
            "reservations": [
                {
                    "authorizations": [
                        {
                            "authorization_id": authorization.authorization_id,
                            "authorization_sha256": authorization.authorization_sha256,
                            "instrument_id": authorization.instrument_id,
                            "intent_id": authorization.intent_id,
                            "remaining_buy_exposure": canonical_decimal_text(
                                authorization.remaining_buy_exposure
                            ),
                            "remaining_cash": canonical_decimal_text(authorization.remaining_cash),
                            "remaining_sell_quantity": canonical_decimal_text(
                                authorization.remaining_sell_quantity
                            ),
                            "reserved_buy_exposure": canonical_decimal_text(
                                authorization.reserved_buy_exposure
                            ),
                            "reserved_cash": canonical_decimal_text(authorization.reserved_cash),
                            "reserved_sell_quantity": canonical_decimal_text(
                                authorization.reserved_sell_quantity
                            ),
                            "side": authorization.side.value,
                        }
                        for authorization in reservation.authorizations
                    ],
                    "currency": reservation.currency,
                    "projection_sha256": reservation.projection_sha256,
                    "provenance_sha256": reservation.provenance_sha256,
                    "reservation_id": reservation.reservation_id,
                    "reservation_sha256": reservation.reservation_sha256,
                    "state": reservation.state.value,
                }
                for reservation in universe.reservations
            ],
            "semantic_sha256": universe.semantic_sha256,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_capacity_decimal(value: object, field_name: str) -> Decimal:
    if type(value) is not str:
        raise BatchRiskFactConflict(f"persisted {field_name} must be canonical decimal text")
    try:
        result = canonical_persisted_decimal(Decimal(value), f"persisted {field_name}")
    except (InvalidOperation, ValueError) as error:
        raise BatchRiskFactConflict(
            f"persisted {field_name} must be canonical decimal text"
        ) from error
    if value != canonical_decimal_text(result):
        raise BatchRiskFactConflict(f"persisted {field_name} is not canonical decimal text")
    return result


def _decode_active_capacity(raw: object) -> ActiveCapacityUniverse:
    if type(raw) is not str:
        raise BatchRiskFactConflict("persisted active capacity payload must be text")
    try:
        decoded = json.loads(raw, object_pairs_hook=_strict_object_pairs)
    except BatchRiskFactConflict:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise BatchRiskFactConflict("persisted active capacity payload is invalid JSON") from error
    expected_root_keys = {
        "account_id",
        "contract_version",
        "persistence_version",
        "reservations",
        "semantic_sha256",
    }
    if type(decoded) is not dict or set(decoded) != expected_root_keys:
        raise BatchRiskFactConflict("persisted active capacity payload has an invalid shape")
    if (
        decoded["contract_version"] != BATCH_RISK_CONTRACT_VERSION
        or decoded["persistence_version"] != PHASE2_BATCH_RISK_PERSISTENCE_VERSION
    ):
        raise BatchRiskFactConflict("persisted active capacity contract is unsupported")
    reservation_values = decoded["reservations"]
    if type(reservation_values) is not list:
        raise BatchRiskFactConflict("persisted active capacity reservations must be an array")
    expected_reservation_keys = {
        "authorizations",
        "currency",
        "projection_sha256",
        "provenance_sha256",
        "reservation_id",
        "reservation_sha256",
        "state",
    }
    expected_authorization_keys = {
        "authorization_id",
        "authorization_sha256",
        "instrument_id",
        "intent_id",
        "remaining_buy_exposure",
        "remaining_cash",
        "remaining_sell_quantity",
        "reserved_buy_exposure",
        "reserved_cash",
        "reserved_sell_quantity",
        "side",
    }
    reservations: list[ActiveCapacityReservation] = []
    try:
        for reservation_index, reservation_value in enumerate(reservation_values):
            if (
                type(reservation_value) is not dict
                or set(reservation_value) != expected_reservation_keys
            ):
                raise BatchRiskFactConflict(
                    "persisted active capacity reservation "
                    f"{reservation_index} has an invalid shape"
                )
            authorization_values = reservation_value["authorizations"]
            if type(authorization_values) is not list:
                raise BatchRiskFactConflict(
                    f"persisted active capacity reservation {reservation_index} children "
                    "must be an array"
                )
            authorizations: list[ActiveCapacityAuthorization] = []
            for authorization_index, authorization_value in enumerate(authorization_values):
                if (
                    type(authorization_value) is not dict
                    or set(authorization_value) != expected_authorization_keys
                ):
                    raise BatchRiskFactConflict(
                        "persisted active capacity authorization "
                        f"{reservation_index}:{authorization_index} has an invalid shape"
                    )
                authorizations.append(
                    ActiveCapacityAuthorization(
                        authorization_id=_require_text(
                            authorization_value["authorization_id"],
                            "active authorization ID",
                        ),
                        authorization_sha256=_require_text(
                            authorization_value["authorization_sha256"],
                            "active authorization digest",
                        ),
                        intent_id=_require_text(
                            authorization_value["intent_id"],
                            "active authorization intent ID",
                        ),
                        instrument_id=_require_text(
                            authorization_value["instrument_id"],
                            "active authorization instrument ID",
                        ),
                        side=Side(
                            _require_text(
                                authorization_value["side"],
                                "active authorization side",
                            )
                        ),
                        reserved_cash=_decode_capacity_decimal(
                            authorization_value["reserved_cash"],
                            "active authorization reserved_cash",
                        ),
                        reserved_sell_quantity=_decode_capacity_decimal(
                            authorization_value["reserved_sell_quantity"],
                            "active authorization reserved_sell_quantity",
                        ),
                        reserved_buy_exposure=_decode_capacity_decimal(
                            authorization_value["reserved_buy_exposure"],
                            "active authorization reserved_buy_exposure",
                        ),
                        remaining_cash=_decode_capacity_decimal(
                            authorization_value["remaining_cash"],
                            "active authorization remaining_cash",
                        ),
                        remaining_sell_quantity=_decode_capacity_decimal(
                            authorization_value["remaining_sell_quantity"],
                            "active authorization remaining_sell_quantity",
                        ),
                        remaining_buy_exposure=_decode_capacity_decimal(
                            authorization_value["remaining_buy_exposure"],
                            "active authorization remaining_buy_exposure",
                        ),
                    )
                )
            reservations.append(
                ActiveCapacityReservation(
                    reservation_id=_require_text(
                        reservation_value["reservation_id"],
                        "active reservation ID",
                    ),
                    reservation_sha256=_require_text(
                        reservation_value["reservation_sha256"],
                        "active reservation digest",
                    ),
                    projection_sha256=_require_text(
                        reservation_value["projection_sha256"],
                        "active reservation projection digest",
                    ),
                    provenance_sha256=_require_text(
                        reservation_value["provenance_sha256"],
                        "active reservation provenance digest",
                    ),
                    currency=_require_text(
                        reservation_value["currency"],
                        "active reservation currency",
                    ),
                    state=ActiveCapacityReservationState(
                        _require_text(
                            reservation_value["state"],
                            "active reservation state",
                        )
                    ),
                    authorizations=tuple(authorizations),
                )
            )
        universe = ActiveCapacityUniverse(
            account_id=_require_text(decoded["account_id"], "active capacity account ID"),
            reservations=tuple(reservations),
        )
    except BatchRiskFactConflict:
        raise
    except (BatchRiskError, KeyError, TypeError, ValueError) as error:
        raise BatchRiskFactConflict("persisted active capacity payload is malformed") from error
    if decoded["semantic_sha256"] != universe.semantic_sha256:
        raise BatchRiskFactConflict("persisted active capacity semantic digest conflicts")
    if raw != _active_capacity_payload(universe):
        raise BatchRiskFactConflict("persisted active capacity payload is not canonical JSON")
    return universe


def _fact_payload(kind: str, semantic_sha256: str) -> str:
    return canonical_json_text(
        (
            PHASE2_BATCH_RISK_PERSISTENCE_VERSION,
            BATCH_RISK_CONTRACT_VERSION,
            kind,
            semantic_sha256,
        )
    )


def _decision_fact_payload(
    decision: BatchRiskDecision,
    active_capacity: ActiveCapacityUniverse,
    account_observation_sequence: int,
    *,
    fencing_generation: int,
    lease_sha256: str,
    fence_sha256: str,
) -> str:
    return canonical_json_text(
        (
            PHASE2_BATCH_RISK_PERSISTENCE_VERSION,
            BATCH_RISK_CONTRACT_VERSION,
            "decision",
            decision.semantic_sha256,
            decision.account_id,
            account_observation_sequence,
            fencing_generation,
            lease_sha256,
            fence_sha256,
            active_capacity.semantic_sha256,
        )
    )


def _batch_member_semantic_sha256(
    *,
    decision_id: str,
    intent_batch_id: str,
    intent_batch_sha256: str,
    ordinal: int,
    intent_id: str,
    intent_payload_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            (
                PHASE2_BATCH_RISK_PERSISTENCE_VERSION,
                "batch_member",
                decision_id,
                intent_batch_id,
                intent_batch_sha256,
                ordinal,
                intent_id,
                intent_payload_sha256,
            )
        )
    ).hexdigest()


def _batch_member_values(
    decision: BatchRiskDecision,
    batch: OrderIntentBatch,
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for ordinal, intent in enumerate(batch.intents):
        payload_sha256 = intent_payload_hash(intent)
        semantic_sha256 = _batch_member_semantic_sha256(
            decision_id=decision.decision_id,
            intent_batch_id=batch.intent_batch_id,
            intent_batch_sha256=batch.semantic_sha256,
            ordinal=ordinal,
            intent_id=intent.intent_id,
            intent_payload_sha256=payload_sha256,
        )
        values.append(
            {
                "membership_id": canonical_id(
                    "phase2-batch-member",
                    decision.decision_id,
                    ordinal,
                    intent.intent_id,
                ),
                "decision_id": decision.decision_id,
                "intent_batch_id": batch.intent_batch_id,
                "intent_batch_sha256": batch.semantic_sha256,
                "ordinal": ordinal,
                "intent_id": intent.intent_id,
                "intent_payload_sha256": payload_sha256,
                "canonical_payload": _fact_payload("batch_member", semantic_sha256),
                "semantic_sha256": semantic_sha256,
            }
        )
    return values


def _fence_values(receipt: AccountFenceReceipt) -> dict[str, object]:
    receipt._validate()
    return {
        "account_id": receipt.fence.account_id,
        "fencing_generation": receipt.fence.fencing_generation,
        "lease_sha256": receipt.lease_sha256,
        "fence_sha256": receipt.fence.semantic_sha256,
    }


def _decision_values(
    decision: BatchRiskDecision,
    receipt: AccountFenceReceipt,
    active_capacity: ActiveCapacityUniverse,
    account_observation_sequence: int,
) -> dict[str, object]:
    if (
        type(active_capacity) is not ActiveCapacityUniverse
        or decision.active_capacity_sha256 != active_capacity.semantic_sha256
        or decision.account_id != active_capacity.account_id
        or any(
            reservation.currency != decision.currency
            for reservation in active_capacity.reservations
        )
    ):
        raise BatchRiskFactConflict(
            "batch decision does not bind its exact active capacity universe"
        )
    if type(account_observation_sequence) is not int or account_observation_sequence <= 0:
        raise BatchRiskFactConflict("batch decision observation sequence must be positive")
    return {
        "decision_id": decision.decision_id,
        "intent_batch_id": decision.intent_batch_id,
        "intent_batch_sha256": decision.intent_batch_sha256,
        **_fence_values(receipt),
        "account_observation_sequence": account_observation_sequence,
        "snapshot_version": decision.snapshot_version,
        "snapshot_sha256": decision.snapshot_sha256,
        "active_capacity_payload": _active_capacity_payload(active_capacity),
        "active_capacity_sha256": decision.active_capacity_sha256,
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "policy_sha256": decision.policy_sha256,
        "currency": decision.currency,
        "status": decision.status.value,
        "evaluated_at": decision.evaluated_at,
        "expires_at": decision.expires_at,
        "intent_count": decision.intent_count,
        "rules_payload": _canonical_rules_payload(decision.rules),
        "canonical_payload": _decision_fact_payload(
            decision,
            active_capacity,
            account_observation_sequence,
            fencing_generation=receipt.fence.fencing_generation,
            lease_sha256=receipt.lease_sha256,
            fence_sha256=receipt.fence.semantic_sha256,
        ),
        "semantic_sha256": decision.semantic_sha256,
    }


def _reservation_values(
    reservation: BatchRiskReservation,
    receipt: AccountFenceReceipt,
    *,
    expires_at: datetime,
) -> dict[str, object]:
    return {
        "reservation_id": reservation.reservation_id,
        "parent_decision_id": reservation.parent_decision_id,
        "intent_batch_id": reservation.intent_batch_id,
        "intent_batch_sha256": reservation.intent_batch_sha256,
        **_fence_values(receipt),
        "snapshot_sha256": reservation.snapshot_sha256,
        "policy_sha256": reservation.policy_sha256,
        "currency": reservation.currency,
        "created_at": receipt.validated_at,
        "expires_at": expires_at,
        "state": "active",
        "state_version": 1,
        "authorization_count": len(reservation.authorizations),
        "remaining_authorization_count": len(reservation.authorizations),
        "initial_cash": reservation.reserved_cash,
        "initial_buy_exposure": reservation.reserved_buy_exposure,
        "remaining_cash": reservation.reserved_cash,
        "remaining_buy_exposure": reservation.reserved_buy_exposure,
        "released_at": None,
        "canonical_payload": _fact_payload("reservation", reservation.semantic_sha256),
        "semantic_sha256": reservation.semantic_sha256,
    }


def _authorization_values(
    authorization: BatchRiskAuthorization,
    receipt: AccountFenceReceipt,
) -> dict[str, object]:
    return {
        "authorization_id": authorization.decision_id,
        "parent_decision_id": authorization.parent_decision_id,
        "reservation_id": authorization.reservation_id,
        "intent_batch_id": authorization.intent_batch_id,
        "intent_batch_sha256": authorization.intent_batch_sha256,
        **_fence_values(receipt),
        "snapshot_sha256": authorization.snapshot_sha256,
        "policy_sha256": authorization.policy_sha256,
        "session_sha256": authorization.session_sha256,
        "currency": authorization.currency,
        "intent_id": authorization.intent_id,
        "intent_payload_sha256": authorization.intent_payload_hash,
        "evaluated_at": authorization.evaluated_at,
        "expires_at": authorization.expires_at,
        "instrument_id": authorization.instrument_id,
        "symbol": authorization.symbol,
        "side": authorization.side.value,
        "quantity": authorization.quantity,
        "reference_price": authorization.reference_price,
        "snapshot_as_of": authorization.snapshot_as_of,
        "reference_event_time": authorization.reference_event_time,
        "maximum_execution_price": authorization.maximum_execution_price,
        "maximum_fee": authorization.maximum_fee,
        "maximum_cash_requirement": authorization.maximum_cash_requirement,
        "reserved_cash": authorization.reserved_cash,
        "reserved_sell_quantity": authorization.reserved_sell_quantity,
        "reserved_buy_exposure": authorization.reserved_buy_exposure,
        "canonical_payload": _fact_payload("authorization", authorization.semantic_sha256),
        "semantic_sha256": authorization.semantic_sha256,
    }


def _envelope_from_row(row: Mapping[str, object]) -> tuple[str, int, str, str]:
    return (
        _require_text(row["account_id"], "account_id"),
        _require_int(row["fencing_generation"], "fencing_generation"),
        _require_text(row["lease_sha256"], "lease_sha256"),
        _require_text(row["fence_sha256"], "fence_sha256"),
    )


def _authenticated_envelope(
    connection: Connection,
    row: Mapping[str, object],
) -> tuple[str, int, str, str]:
    account_id, generation, lease_sha256, fence_sha256 = _envelope_from_row(row)
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
        raise BatchRiskFactConflict("persisted batch fence references a missing lease")
    try:
        lease = account_lease_from_row(lease_row)
    except (BatchRiskError, ValueError) as error:
        raise BatchRiskFactConflict("persisted batch fence lease evidence is malformed") from error
    if lease.fence.semantic_sha256 != fence_sha256:
        raise BatchRiskFactConflict("persisted batch fence digest conflicts with its lease")
    return account_id, generation, lease_sha256, fence_sha256


def _batch_member_rows(
    connection: Connection,
    decision_id: str,
) -> tuple[RowMapping, ...]:
    return tuple(
        connection.execute(
            sa.select(phase2_batch_members)
            .where(phase2_batch_members.c.decision_id == decision_id)
            .order_by(phase2_batch_members.c.ordinal)
        )
        .mappings()
        .all()
    )


def _decode_batch_members(
    connection: Connection,
    decision_id: str,
) -> tuple[tuple[str, str], ...]:
    rows = _batch_member_rows(connection, decision_id)
    result: list[tuple[str, str]] = []
    for expected_ordinal, row in enumerate(rows):
        ordinal = _require_int(
            row["ordinal"],
            "batch member ordinal",
            non_negative=True,
        )
        if ordinal != expected_ordinal:
            raise BatchRiskFactConflict("persisted batch member ordinals are not contiguous")
        persisted_decision_id = _require_text(row["decision_id"], "batch member decision_id")
        intent_batch_id = _require_text(row["intent_batch_id"], "batch member intent_batch_id")
        intent_batch_sha256 = _require_text(
            row["intent_batch_sha256"], "batch member intent_batch_sha256"
        )
        intent_id = _require_text(row["intent_id"], "batch member intent_id")
        intent_sha256 = _require_text(
            row["intent_payload_sha256"], "batch member intent payload digest"
        )
        expected_id = canonical_id(
            "phase2-batch-member",
            decision_id,
            ordinal,
            intent_id,
        )
        semantic_sha256 = _batch_member_semantic_sha256(
            decision_id=decision_id,
            intent_batch_id=intent_batch_id,
            intent_batch_sha256=intent_batch_sha256,
            ordinal=ordinal,
            intent_id=intent_id,
            intent_payload_sha256=intent_sha256,
        )
        if (
            persisted_decision_id != decision_id
            or row["membership_id"] != expected_id
            or row["semantic_sha256"] != semantic_sha256
            or row["canonical_payload"] != _fact_payload("batch_member", semantic_sha256)
        ):
            raise BatchRiskFactConflict("persisted batch member identity is inconsistent")
        result.append((intent_id, intent_sha256))
    return tuple(result)


def _authorization_from_row(row: RowMapping) -> BatchRiskAuthorization:
    try:
        side_raw = _require_text(row["side"], "authorization side")
        authorization = BatchRiskAuthorization(
            decision_id=_require_text(row["authorization_id"], "authorization_id"),
            parent_decision_id=_require_text(
                row["parent_decision_id"], "authorization parent_decision_id"
            ),
            reservation_id=_require_text(row["reservation_id"], "authorization reservation_id"),
            intent_batch_id=_require_text(row["intent_batch_id"], "authorization intent_batch_id"),
            intent_batch_sha256=_require_text(
                row["intent_batch_sha256"], "authorization intent_batch_sha256"
            ),
            snapshot_sha256=_require_text(row["snapshot_sha256"], "authorization snapshot_sha256"),
            policy_sha256=_require_text(row["policy_sha256"], "authorization policy_sha256"),
            session_sha256=_require_text(row["session_sha256"], "authorization session_sha256"),
            currency=_require_text(row["currency"], "authorization currency"),
            intent_id=_require_text(row["intent_id"], "authorization intent_id"),
            intent_payload_hash=_require_text(
                row["intent_payload_sha256"], "authorization intent payload digest"
            ),
            status=DecisionStatus.APPROVED,
            evaluated_at=_require_datetime(row["evaluated_at"], "authorization evaluated_at"),
            expires_at=_require_datetime(row["expires_at"], "authorization expires_at"),
            instrument_id=_require_text(row["instrument_id"], "authorization instrument_id"),
            symbol=_require_text(row["symbol"], "authorization symbol"),
            side=Side(side_raw),
            quantity=_require_decimal(row["quantity"], "authorization quantity", positive=True),
            reference_price=_require_decimal(
                row["reference_price"], "authorization reference_price", positive=True
            ),
            snapshot_as_of=_require_datetime(row["snapshot_as_of"], "authorization snapshot_as_of"),
            reference_event_time=_require_datetime(
                row["reference_event_time"], "authorization reference_event_time"
            ),
            maximum_execution_price=_require_decimal(
                row["maximum_execution_price"],
                "authorization maximum_execution_price",
                positive=True,
            ),
            maximum_fee=_require_decimal(row["maximum_fee"], "authorization maximum_fee"),
            maximum_cash_requirement=_require_decimal(
                row["maximum_cash_requirement"],
                "authorization maximum_cash_requirement",
            ),
            reserved_cash=_require_decimal(row["reserved_cash"], "authorization reserved_cash"),
            reserved_sell_quantity=_require_decimal(
                row["reserved_sell_quantity"],
                "authorization reserved_sell_quantity",
            ),
            reserved_buy_exposure=_require_decimal(
                row["reserved_buy_exposure"],
                "authorization reserved_buy_exposure",
            ),
        )
    except BatchRiskFactConflict:
        raise
    except (BatchRiskError, KeyError, TypeError, ValueError) as error:
        raise BatchRiskFactConflict("persisted batch authorization is malformed") from error
    if row["semantic_sha256"] != authorization.semantic_sha256 or row[
        "canonical_payload"
    ] != _fact_payload("authorization", authorization.semantic_sha256):
        raise BatchRiskFactConflict("persisted batch authorization digest is inconsistent")
    return authorization


def _reservation_from_rows(
    row: RowMapping,
    authorizations: tuple[BatchRiskAuthorization, ...],
) -> BatchRiskReservation:
    try:
        reservation = BatchRiskReservation(
            reservation_id=_require_text(row["reservation_id"], "reservation_id"),
            parent_decision_id=_require_text(
                row["parent_decision_id"], "reservation parent_decision_id"
            ),
            intent_batch_id=_require_text(row["intent_batch_id"], "reservation intent_batch_id"),
            intent_batch_sha256=_require_text(
                row["intent_batch_sha256"], "reservation intent_batch_sha256"
            ),
            snapshot_sha256=_require_text(row["snapshot_sha256"], "reservation snapshot_sha256"),
            policy_sha256=_require_text(row["policy_sha256"], "reservation policy_sha256"),
            currency=_require_text(row["currency"], "reservation currency"),
            authorizations=authorizations,
            reserved_cash=_require_decimal(row["initial_cash"], "reservation initial_cash"),
            reserved_buy_exposure=_require_decimal(
                row["initial_buy_exposure"], "reservation initial_buy_exposure"
            ),
        )
    except BatchRiskFactConflict:
        raise
    except (BatchRiskError, KeyError, TypeError, ValueError) as error:
        raise BatchRiskFactConflict("persisted batch reservation is malformed") from error
    if row["semantic_sha256"] != reservation.semantic_sha256 or row[
        "canonical_payload"
    ] != _fact_payload("reservation", reservation.semantic_sha256):
        raise BatchRiskFactConflict("persisted batch reservation digest is inconsistent")
    if _require_int(row["state_version"], "reservation state_version") < 1:
        raise BatchRiskFactConflict("persisted reservation state version is invalid")
    authorization_count = _require_int(
        row["authorization_count"], "reservation authorization_count"
    )
    remaining_count = _require_int(
        row["remaining_authorization_count"],
        "reservation remaining_authorization_count",
        non_negative=True,
    )
    if authorization_count != len(authorizations) or remaining_count > authorization_count:
        raise BatchRiskFactConflict("persisted reservation authorization counts are inconsistent")
    remaining_cash = _require_decimal(row["remaining_cash"], "reservation remaining_cash")
    remaining_exposure = _require_decimal(
        row["remaining_buy_exposure"], "reservation remaining_buy_exposure"
    )
    if (
        remaining_cash > reservation.reserved_cash
        or remaining_exposure > reservation.reserved_buy_exposure
    ):
        raise BatchRiskFactConflict("persisted reservation remaining holds exceed initial holds")
    state = _require_text(row["state"], "reservation state")
    released_at = row["released_at"]
    if state == "released":
        if (
            released_at is None
            or remaining_count != 0
            or remaining_cash != 0
            or remaining_exposure != 0
        ):
            raise BatchRiskFactConflict("persisted released reservation retains capacity")
        _require_datetime(released_at, "reservation released_at")
    elif state in {"active", "partially_released", "frozen"}:
        if released_at is not None or remaining_count == 0:
            raise BatchRiskFactConflict("persisted active reservation state is inconsistent")
    else:
        raise BatchRiskFactConflict("persisted reservation state is unsupported")
    return reservation


def _authorization_rows(
    connection: Connection,
    parent_decision_id: str,
) -> tuple[RowMapping, ...]:
    return tuple(
        connection.execute(
            sa.select(phase2_batch_authorizations)
            .join(
                phase2_batch_members,
                sa.and_(
                    phase2_batch_members.c.decision_id
                    == phase2_batch_authorizations.c.parent_decision_id,
                    phase2_batch_members.c.intent_id == phase2_batch_authorizations.c.intent_id,
                ),
            )
            .where(phase2_batch_authorizations.c.parent_decision_id == parent_decision_id)
            .order_by(phase2_batch_members.c.ordinal)
        )
        .mappings()
        .all()
    )


def load_batch_risk_decision(
    connection: Connection,
    decision_id: str,
) -> BatchRiskDecision | None:
    """Strictly reconstruct one complete decision from its normalized SQL facts."""

    row = (
        connection.execute(
            sa.select(phase2_batch_decisions).where(
                phase2_batch_decisions.c.decision_id == decision_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    try:
        authorization_rows = _authorization_rows(connection, decision_id)
        authorizations = tuple(_authorization_from_row(item) for item in authorization_rows)
        decision_envelope = _authenticated_envelope(
            connection,
            cast(Mapping[str, object], row),
        )
        if any(
            _authenticated_envelope(
                connection,
                cast(Mapping[str, object], item),
            )
            != decision_envelope
            for item in authorization_rows
        ):
            raise BatchRiskFactConflict("persisted child authorization fence bindings disagree")
        reservation_row = (
            connection.execute(
                sa.select(phase2_batch_reservations).where(
                    phase2_batch_reservations.c.parent_decision_id == decision_id
                )
            )
            .mappings()
            .one_or_none()
        )
        reservation = (
            None
            if reservation_row is None
            else _reservation_from_rows(reservation_row, authorizations)
        )
        if (
            reservation_row is not None
            and _authenticated_envelope(
                connection,
                cast(Mapping[str, object], reservation_row),
            )
            != decision_envelope
        ):
            raise BatchRiskFactConflict("persisted reservation fence binding disagrees")
        active_capacity = _decode_active_capacity(row["active_capacity_payload"])
        if (
            active_capacity.account_id != row["account_id"]
            or row["active_capacity_sha256"] != active_capacity.semantic_sha256
            or any(
                reservation.currency != row["currency"]
                for reservation in active_capacity.reservations
            )
        ):
            raise BatchRiskFactConflict(
                "persisted batch decision active capacity binding disagrees"
            )
        preverified_capacity = tuple(
            _historical_active_capacity(
                connection,
                item,
                observing_decision_id=_require_text(row["decision_id"], "decision_id"),
                account_id=_require_text(row["account_id"], "account_id"),
                currency=_require_text(row["currency"], "currency"),
                evaluated_at=_require_datetime(row["evaluated_at"], "decision evaluated_at"),
            )[0]
            for item in active_capacity.reservations
        )
        if preverified_capacity != active_capacity.reservations:
            raise BatchRiskFactConflict(
                "persisted batch decision active capacity is not authenticated"
            )
        observation_sequence = _require_int(
            row["account_observation_sequence"],
            "decision account observation sequence",
        )
        _verify_capacity_observation_completeness(
            connection,
            active_capacity,
            observation_sequence,
            decision_id=_require_text(row["decision_id"], "decision_id"),
            account_id=_require_text(row["account_id"], "account_id"),
            currency=_require_text(row["currency"], "currency"),
            evaluated_at=_require_datetime(row["evaluated_at"], "decision evaluated_at"),
        )
        status_raw = _require_text(row["status"], "batch decision status")
        decision = BatchRiskDecision(
            decision_id=_require_text(row["decision_id"], "decision_id"),
            intent_batch_id=_require_text(row["intent_batch_id"], "intent_batch_id"),
            intent_batch_sha256=_require_text(row["intent_batch_sha256"], "intent_batch_sha256"),
            account_id=_require_text(row["account_id"], "account_id"),
            snapshot_version=_require_text(row["snapshot_version"], "snapshot_version"),
            snapshot_sha256=_require_text(row["snapshot_sha256"], "snapshot_sha256"),
            active_capacity_sha256=_require_text(
                row["active_capacity_sha256"],
                "active capacity digest",
            ),
            policy_id=_require_text(row["policy_id"], "policy_id"),
            policy_version=_require_text(row["policy_version"], "policy_version"),
            policy_sha256=_require_text(row["policy_sha256"], "policy_sha256"),
            currency=_require_text(row["currency"], "currency"),
            status=BatchRiskDecisionStatus(status_raw),
            evaluated_at=_require_datetime(row["evaluated_at"], "decision evaluated_at"),
            expires_at=_require_datetime(row["expires_at"], "decision expires_at"),
            intent_count=_require_int(
                row["intent_count"], "decision intent_count", non_negative=True
            ),
            rules=_decode_rules(row["rules_payload"]),
            reservation=reservation,
            authorizations=authorizations,
        )
        members = _decode_batch_members(connection, decision.decision_id)
        if len(members) != decision.intent_count:
            raise BatchRiskFactConflict("persisted batch member count conflicts with its decision")
        if any(
            member_row["intent_batch_id"] != decision.intent_batch_id
            or member_row["intent_batch_sha256"] != decision.intent_batch_sha256
            for member_row in _batch_member_rows(connection, decision.decision_id)
        ):
            raise BatchRiskFactConflict("persisted batch members disagree with their decision")
        if decision.status is BatchRiskDecisionStatus.APPROVED and members != tuple(
            (authorization.intent_id, authorization.intent_payload_hash)
            for authorization in decision.authorizations
        ):
            raise BatchRiskFactConflict(
                "persisted approved batch members disagree with their authorizations"
            )
        if reservation_row is not None and (
            _require_datetime(reservation_row["created_at"], "reservation created_at")
            != decision.evaluated_at
            or _require_datetime(reservation_row["expires_at"], "reservation expires_at")
            != decision.expires_at
        ):
            raise BatchRiskFactConflict("persisted reservation timing disagrees with its decision")
    except BatchRiskFactConflict:
        raise
    except (BatchRiskError, KeyError, TypeError, ValueError) as error:
        raise BatchRiskFactConflict("persisted batch decision is malformed") from error
    if row["semantic_sha256"] != decision.semantic_sha256 or row[
        "canonical_payload"
    ] != _decision_fact_payload(
        decision,
        active_capacity,
        observation_sequence,
        fencing_generation=decision_envelope[1],
        lease_sha256=decision_envelope[2],
        fence_sha256=decision_envelope[3],
    ):
        raise BatchRiskFactConflict("persisted batch decision digest is inconsistent")
    return decision


def _strict_release_history(
    connection: Connection,
    reservation: BatchRiskReservation,
) -> tuple[ReservationReleaseFact, ...]:
    """Decode release rows directly, avoiding the decision-loader dependency cycle."""

    # This decoder rebuilds each fact from normalized fields and verifies its
    # canonical identity.  Importing lazily avoids the lifecycle repository's
    # reverse import of this module.
    from packages.persistence.reservation_lifecycle import (
        ReservationLifecyclePersistenceError,
        reservation_release_from_row,
    )

    try:
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
    except (ReservationLifecycleError, ReservationLifecyclePersistenceError) as error:
        raise BatchRiskFactConflict("reservation release history is not canonical") from error
    return ordered


def _attempts_at(
    connection: Connection,
    parent_decision_id: str,
    *,
    as_of: datetime | None,
) -> tuple[CanonicalSubmissionAttempt, ...]:
    """Strictly rebuild each attempt's immutable event prefix at an observation."""

    from packages.persistence.submission_attempt import (
        SubmissionAttemptPersistenceError,
        load_submission_attempt,
    )

    attempt_ids = tuple(
        str(value)
        for value in connection.scalars(
            sa.select(phase2_submission_attempts.c.attempt_id)
            .where(phase2_submission_attempts.c.parent_decision_id == parent_decision_id)
            .order_by(
                phase2_submission_attempts.c.order_id,
                phase2_submission_attempts.c.attempt_number,
                phase2_submission_attempts.c.attempt_id,
            )
        )
    )
    result: list[CanonicalSubmissionAttempt] = []
    for attempt_id in attempt_ids:
        try:
            current = load_submission_attempt(connection, attempt_id)
        except SubmissionAttemptPersistenceError as error:
            raise BatchRiskFactConflict(
                "capacity provenance references malformed submission evidence"
            ) from error
        if current is None:  # pragma: no cover - selected immediately above
            raise BatchRiskFactConflict("capacity provenance submission disappeared")
        if as_of is None:
            result.append(current)
            continue
        if current.preparation.prepared_at > as_of:
            continue
        prefix = tuple(event for event in current.events if event.recorded_at <= as_of)
        if not prefix:
            raise BatchRiskFactConflict(
                "capacity provenance attempt preparation lacks its pending fact"
            )
        try:
            result.append(reduce_submission_attempt(current.preparation, prefix))
        except SubmissionAttemptError as error:
            raise BatchRiskFactConflict(
                "capacity provenance attempt prefix is not canonical"
            ) from error
    return tuple(result)


def _order_state_at(
    connection: Connection,
    attempt: CanonicalSubmissionAttempt,
    *,
    as_of: datetime | None,
) -> CanonicalOrderState:
    """Rebuild the exact immutable order-event prefix visible at an observation."""

    from packages.persistence.reservation_lifecycle import (
        ReservationLifecyclePersistenceError,
        load_canonical_order_state,
    )

    try:
        current = load_canonical_order_state(connection, attempt.attempt_id)
    except ReservationLifecyclePersistenceError as error:
        raise BatchRiskFactConflict(
            "capacity provenance references malformed order evidence"
        ) from error
    if current is None:
        raise BatchRiskFactConflict("capacity provenance references a missing logical order")
    if as_of is None:
        return current
    events = tuple(event for event in current.broker_events if event.received_at <= as_of)
    cancel_request = current.cancel_request
    if cancel_request is not None and cancel_request.requested_at > as_of:
        cancel_request = None
    if cancel_request is not None and not any(
        event.kind is BrokerOrderEventKind.CANCELED for event in events
    ):
        cancel_request = None
    try:
        return reduce_order_lifecycle(
            submission=current.submission,
            broker_events=events,
            cancel_request=cancel_request,
        )
    except OrderLifecycleError as error:
        raise BatchRiskFactConflict("capacity provenance order prefix is not canonical") from error


_CORRECTION_CLOSURE_REASONS = frozenset(
    {
        ReservationReleaseReason.RECONCILED_TERMINAL,
        ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
    }
)


def _freeze_provenance_material(
    connection: Connection,
    reservation: BatchRiskReservation,
    history: tuple[ReservationReleaseFact, ...],
    *,
    as_of: datetime | None,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    """Return exact UNKNOWN and non-monotone-correction freeze evidence."""

    attempts = _attempts_at(
        connection,
        reservation.parent_decision_id,
        as_of=as_of,
    )
    unknown = tuple(
        (
            attempt.attempt_id,
            attempt.preparation.authorization_id,
            attempt.semantic_sha256,
            attempt.events[-1].semantic_sha256,
        )
        for attempt in attempts
        if attempt.state is SubmissionAttemptState.UNKNOWN
    )

    latest_by_authorization: dict[str, CanonicalSubmissionAttempt] = {}
    for attempt in attempts:
        current = latest_by_authorization.get(attempt.preparation.authorization_id)
        if current is None or attempt.attempt_number > current.attempt_number:
            latest_by_authorization[attempt.preparation.authorization_id] = attempt
    corrections: list[tuple[object, ...]] = []
    for attempt in latest_by_authorization.values():
        order_state = _order_state_at(connection, attempt, as_of=as_of)
        for execution in order_state.executions:
            matches = tuple(
                event for event in order_state.broker_events if event.event_id == execution.event_id
            )
            if len(matches) != 1:
                raise BatchRiskFactConflict(
                    "capacity provenance execution lacks its exact broker event"
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
            prior_accounting = tuple(
                fact
                for fact in history
                if fact.authorization_id == attempt.preparation.authorization_id
                and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
                and fact.execution_id == execution.execution_id
                and fact.accounted_quantity is not None
            )
            prior_accounted = exact_decimal_sum(
                fact.accounted_quantity
                for fact in prior_accounting
                if fact.accounted_quantity is not None
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
                corrections.append(
                    (
                        attempt.attempt_id,
                        attempt.semantic_sha256,
                        order_state.semantic_sha256,
                        event.event_id,
                        event.semantic_sha256,
                        execution.semantic_sha256,
                        tuple(fact.semantic_sha256 for fact in prior_accounting),
                    )
                )
    return unknown, tuple(sorted(corrections))


def _capacity_provenance_sha256(
    connection: Connection,
    reservation: BatchRiskReservation,
    projection: ReservationCapacityProjection,
    state: ActiveCapacityReservationState,
    history: tuple[ReservationReleaseFact, ...],
    *,
    as_of: datetime | None,
) -> str:
    unknown, corrections = _freeze_provenance_material(
        connection,
        reservation,
        history,
        as_of=as_of,
    )
    frozen = bool(unknown or corrections)
    if frozen != (state is ActiveCapacityReservationState.FROZEN):
        raise BatchRiskFactConflict(
            "reservation mutable head disagrees with immutable freeze provenance"
        )
    return hashlib.sha256(
        canonical_json_bytes(
            (
                PHASE2_BATCH_RISK_PERSISTENCE_VERSION,
                BATCH_RISK_CONTRACT_VERSION,
                "active_capacity_provenance",
                reservation.semantic_sha256,
                projection.semantic_sha256,
                state.value,
                tuple(fact.semantic_sha256 for fact in history),
                unknown,
                corrections,
            )
        )
    ).hexdigest()


def _capacity_reservation_from_sql(
    connection: Connection,
    reservation_id: str,
    *,
    observing_decision_id: str,
    account_id: str,
    currency: str,
) -> tuple[RowMapping, RowMapping, BatchRiskReservation]:
    """Reconstruct referenced reservation/auth facts without loading its decision."""

    reservation_row = (
        connection.execute(
            sa.select(phase2_batch_reservations).where(
                phase2_batch_reservations.c.reservation_id == reservation_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if reservation_row is None:
        raise BatchRiskFactConflict("persisted active capacity references a missing reservation")
    parent_decision_id = _require_text(
        reservation_row["parent_decision_id"],
        "active reservation parent decision ID",
    )
    if parent_decision_id == observing_decision_id:
        raise BatchRiskFactConflict(
            "batch decision cannot charge its own newly-created reservation"
        )
    parent_row = (
        connection.execute(
            sa.select(phase2_batch_decisions).where(
                phase2_batch_decisions.c.decision_id == parent_decision_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if parent_row is None:
        raise BatchRiskFactConflict(
            "persisted active capacity reservation lacks its parent decision"
        )
    authorization_rows = _authorization_rows(connection, parent_decision_id)
    authorizations = tuple(_authorization_from_row(row) for row in authorization_rows)
    reservation = _reservation_from_rows(reservation_row, authorizations)
    reservation_envelope = _authenticated_envelope(
        connection,
        cast(Mapping[str, object], reservation_row),
    )
    if _authenticated_envelope(
        connection, cast(Mapping[str, object], parent_row)
    ) != reservation_envelope or any(
        _authenticated_envelope(connection, cast(Mapping[str, object], row)) != reservation_envelope
        for row in authorization_rows
    ):
        raise BatchRiskFactConflict("active capacity reservation fence facts disagree")
    if (
        parent_row["status"] != BatchRiskDecisionStatus.APPROVED.value
        or parent_row["account_id"] != account_id
        or reservation_row["account_id"] != account_id
        or reservation.currency != currency
        or parent_row["currency"] != currency
        or parent_row["intent_batch_id"] != reservation.intent_batch_id
        or parent_row["intent_batch_sha256"] != reservation.intent_batch_sha256
        or parent_row["snapshot_sha256"] != reservation.snapshot_sha256
        or parent_row["policy_sha256"] != reservation.policy_sha256
        or _require_datetime(parent_row["evaluated_at"], "parent decision evaluated_at")
        != _require_datetime(reservation_row["created_at"], "reservation created_at")
        or _require_datetime(parent_row["expires_at"], "parent decision expires_at")
        != _require_datetime(reservation_row["expires_at"], "reservation expires_at")
    ):
        raise BatchRiskFactConflict(
            "active capacity reservation changed its exact parent decision facts"
        )
    return reservation_row, parent_row, reservation


def _historical_active_capacity(
    connection: Connection,
    persisted: ActiveCapacityReservation,
    *,
    observing_decision_id: str,
    account_id: str,
    currency: str,
    evaluated_at: datetime,
) -> tuple[ActiveCapacityReservation, RowMapping]:
    """Authenticate one stored capacity item as an exact historical prefix."""

    _reservation_row, parent_row, reservation = _capacity_reservation_from_sql(
        connection,
        persisted.reservation_id,
        observing_decision_id=observing_decision_id,
        account_id=account_id,
        currency=currency,
    )
    if reservation.semantic_sha256 != persisted.reservation_sha256:
        raise BatchRiskFactConflict(
            "persisted active capacity reservation digest conflicts with SQL facts"
        )
    history = _strict_release_history(connection, reservation)
    matches: list[ActiveCapacityReservation] = []
    for prefix_length in range(len(history) + 1):
        prefix = history[:prefix_length]
        suffix = history[prefix_length:]
        if any(fact.recorded_at > evaluated_at for fact in prefix):
            continue
        if any(fact.recorded_at < evaluated_at for fact in suffix):
            continue
        try:
            projection = project_reservation_capacity(reservation, prefix)
        except ReservationLifecycleError as error:  # pragma: no cover - full chain checked above
            raise BatchRiskFactConflict(
                "historical capacity release prefix is not canonical"
            ) from error
        if projection.semantic_sha256 != persisted.projection_sha256:
            continue
        provenance_sha256 = _capacity_provenance_sha256(
            connection,
            reservation,
            projection,
            persisted.state,
            prefix,
            as_of=evaluated_at,
        )
        if provenance_sha256 != persisted.provenance_sha256:
            continue
        try:
            projected = _project_active_capacity(
                reservation,
                projection,
                persisted.state,
                provenance_sha256,
            )
        except BatchRiskFactConflict:
            continue
        if projected == persisted:
            matches.append(projected)
    if len(matches) != 1:
        raise BatchRiskFactConflict(
            "persisted active capacity is not one authenticated historical lifecycle prefix"
        )
    return matches[0], parent_row


def _verify_capacity_observation_completeness(
    connection: Connection,
    active_capacity: ActiveCapacityUniverse,
    observation_sequence: int,
    *,
    decision_id: str,
    account_id: str,
    currency: str,
    evaluated_at: datetime,
) -> None:
    """Prove the universe contains every prior nonterminal reservation."""

    observation_rows = _account_observation_rows(connection, account_id)
    prefix = tuple(
        row
        for row in observation_rows
        if _require_int(
            row["account_observation_sequence"],
            "account observation sequence",
        )
        <= observation_sequence
    )
    if tuple(
        _require_int(row["account_observation_sequence"], "account observation sequence")
        for row in prefix
    ) != tuple(range(1, observation_sequence + 1)):
        raise BatchRiskFactConflict(
            "account decision observation sequence prefix is not contiguous"
        )
    if not prefix or prefix[-1]["decision_id"] != decision_id:
        raise BatchRiskFactConflict(
            "batch decision does not occupy its claimed account observation sequence"
        )

    included = {item.reservation_id: item for item in active_capacity.reservations}
    candidate_rows = tuple(
        connection.execute(
            sa.select(
                phase2_batch_reservations.c.reservation_id,
                phase2_batch_decisions.c.account_observation_sequence,
            )
            .join(
                phase2_batch_decisions,
                phase2_batch_decisions.c.decision_id
                == phase2_batch_reservations.c.parent_decision_id,
            )
            .where(
                phase2_batch_reservations.c.account_id == account_id,
                phase2_batch_decisions.c.account_observation_sequence < observation_sequence,
            )
            .order_by(phase2_batch_decisions.c.account_observation_sequence)
        )
        .mappings()
        .all()
    )
    candidate_ids = {
        _require_text(row["reservation_id"], "prior reservation ID") for row in candidate_rows
    }
    if not set(included).issubset(candidate_ids):
        raise BatchRiskFactConflict("active capacity contains a non-prior reservation observation")
    for row in candidate_rows:
        reservation_id = _require_text(row["reservation_id"], "prior reservation ID")
        if reservation_id in included:
            continue
        _reservation_row, _parent_row, reservation = _capacity_reservation_from_sql(
            connection,
            reservation_id,
            observing_decision_id=decision_id,
            account_id=account_id,
            currency=currency,
        )
        history = _strict_release_history(connection, reservation)
        strict_prior = tuple(fact for fact in history if fact.recorded_at < evaluated_at)
        try:
            projection = project_reservation_capacity(reservation, strict_prior)
        except ReservationLifecycleError as error:  # pragma: no cover - full chain checked above
            raise BatchRiskFactConflict(
                "prior reservation lifecycle prefix is not canonical"
            ) from error
        if projection.state is not ReservationCapacityState.RELEASED:
            raise BatchRiskFactConflict(
                "persisted active capacity omits a prior reservation without "
                "strictly earlier terminal release evidence"
            )


def _active_reservation_evidence(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime | None = None,
) -> tuple[
    tuple[
        BatchRiskReservation,
        ReservationCapacityProjection,
        ActiveCapacityReservationState,
        str,
    ],
    ...,
]:
    rows = tuple(
        connection.execute(
            sa.select(phase2_batch_reservations)
            .where(
                phase2_batch_reservations.c.account_id == account_id,
            )
            .order_by(phase2_batch_reservations.c.reservation_id)
        )
        .mappings()
        .all()
    )
    result: list[
        tuple[
            BatchRiskReservation,
            ReservationCapacityProjection,
            ActiveCapacityReservationState,
            str,
        ]
    ] = []
    for row in rows:
        parent_decision_id = _require_text(
            row["parent_decision_id"],
            "reservation parent_decision_id",
        )
        decision = load_batch_risk_decision(connection, parent_decision_id)
        if decision is None or decision.reservation is None:
            raise BatchRiskFactConflict("reservation lacks its complete approved parent decision")
        reservation = decision.reservation
        projection, history = _authenticate_reservation_head(
            connection,
            row,
            reservation,
            as_of=as_of,
        )
        if projection.state is ReservationCapacityState.RELEASED:
            continue
        try:
            persisted_state = ActiveCapacityReservationState(
                _require_text(row["state"], "reservation state")
            )
        except ValueError as error:
            raise BatchRiskFactConflict(
                "active reservation uses an unsupported capacity state"
            ) from error
        provenance_sha256 = _capacity_provenance_sha256(
            connection,
            reservation,
            projection,
            persisted_state,
            history,
            as_of=as_of,
        )
        result.append((reservation, projection, persisted_state, provenance_sha256))
    return tuple(result)


def _active_reservations(
    connection: Connection,
    account_id: str,
) -> tuple[BatchRiskReservation, ...]:
    return tuple(
        reservation
        for reservation, _projection, _state, _provenance in _active_reservation_evidence(
            connection,
            account_id,
        )
    )


def _project_active_capacity(
    reservation: BatchRiskReservation,
    projection: ReservationCapacityProjection,
    state: ActiveCapacityReservationState,
    provenance_sha256: str,
) -> ActiveCapacityReservation:
    if (
        projection.reservation_id != reservation.reservation_id
        or projection.reservation_sha256 != reservation.semantic_sha256
        or projection.parent_decision_id != reservation.parent_decision_id
    ):
        raise BatchRiskFactConflict("capacity projection changed its reservation evidence")
    authorization_by_id = {
        authorization.decision_id: authorization for authorization in reservation.authorizations
    }
    active_authorizations: list[ActiveCapacityAuthorization] = []
    for child in projection.authorizations:
        authorization = authorization_by_id.get(child.authorization_id)
        if authorization is None:
            raise BatchRiskFactConflict("capacity projection contains an unknown child")
        if (
            child.instrument_id != authorization.instrument_id
            or child.side is not authorization.side
            or child.initial_cash != authorization.reserved_cash
            or child.initial_buy_exposure != authorization.reserved_buy_exposure
            or child.initial_sell_quantity != authorization.reserved_sell_quantity
        ):
            raise BatchRiskFactConflict("capacity projection changed its authorization evidence")
        if child.fully_released:
            continue
        active_authorizations.append(
            ActiveCapacityAuthorization(
                authorization_id=authorization.decision_id,
                authorization_sha256=authorization.semantic_sha256,
                intent_id=authorization.intent_id,
                instrument_id=authorization.instrument_id,
                side=authorization.side,
                reserved_cash=authorization.reserved_cash,
                reserved_sell_quantity=authorization.reserved_sell_quantity,
                reserved_buy_exposure=authorization.reserved_buy_exposure,
                remaining_cash=child.remaining_cash,
                remaining_sell_quantity=child.remaining_sell_quantity,
                remaining_buy_exposure=child.remaining_buy_exposure,
            )
        )
    if len(active_authorizations) != projection.remaining_authorization_count:
        raise BatchRiskFactConflict("capacity projection remaining child count is inconsistent")
    projected = ActiveCapacityReservation(
        reservation_id=reservation.reservation_id,
        reservation_sha256=reservation.semantic_sha256,
        projection_sha256=projection.semantic_sha256,
        provenance_sha256=provenance_sha256,
        currency=reservation.currency,
        state=state,
        authorizations=tuple(active_authorizations),
    )
    projected_sell = {
        item.instrument_id: item.remaining_quantity
        for item in projection.sell_capacity
        if item.remaining_quantity > 0
    }
    active_sell: dict[str, Decimal] = {}
    for active_authorization in projected.authorizations:
        if active_authorization.remaining_sell_quantity == 0:
            continue
        active_sell[active_authorization.instrument_id] = exact_decimal_add(
            active_sell.get(active_authorization.instrument_id, Decimal(0)),
            active_authorization.remaining_sell_quantity,
        )
    if (
        projected.remaining_cash != projection.remaining_cash
        or projected.remaining_buy_exposure != projection.remaining_buy_exposure
        or active_sell != projected_sell
    ):
        raise BatchRiskFactConflict(
            "risk-facing active capacity differs from its lifecycle projection"
        )
    return projected


def _active_capacity_universe(
    connection: Connection,
    account_id: str,
    *,
    as_of: datetime | None = None,
) -> ActiveCapacityUniverse:
    return ActiveCapacityUniverse(
        account_id=account_id,
        reservations=tuple(
            _project_active_capacity(reservation, projection, state, provenance_sha256)
            for reservation, projection, state, provenance_sha256 in _active_reservation_evidence(
                connection,
                account_id,
                as_of=as_of,
            )
        ),
    )


def _authenticate_reservation_head(
    connection: Connection,
    row: RowMapping,
    reservation: BatchRiskReservation,
    *,
    as_of: datetime | None = None,
) -> tuple[ReservationCapacityProjection, tuple[ReservationReleaseFact, ...]]:
    """Reconcile one mutable reservation head to its append-only release facts."""

    try:
        history = _strict_release_history(connection, reservation)
        if as_of is not None and any(fact.recorded_at > as_of for fact in history):
            raise BatchRiskFactConflict(
                "reservation head contains release evidence after the risk observation"
            )
        projection = project_reservation_capacity(reservation, history)
    except ReservationLifecycleError as error:
        raise BatchRiskFactConflict("reservation release history is not canonical") from error

    persisted_state = _require_text(row["state"], "reservation state")
    expected_state = projection.state.value
    state_matches = persisted_state == expected_state or (
        persisted_state == ReservationCapacityState.FROZEN.value
        and projection.state
        in (
            ReservationCapacityState.ACTIVE,
            ReservationCapacityState.PARTIALLY_RELEASED,
        )
    )
    released_at = row["released_at"]
    persisted_released_at = (
        None if released_at is None else _require_datetime(released_at, "reservation released_at")
    )
    if (
        not state_matches
        or _require_int(
            row["authorization_count"],
            "reservation authorization_count",
        )
        != projection.authorization_count
        or _require_int(
            row["remaining_authorization_count"],
            "reservation remaining_authorization_count",
            non_negative=True,
        )
        != projection.remaining_authorization_count
        or _require_decimal(row["initial_cash"], "reservation initial_cash")
        != projection.initial_cash
        or _require_decimal(row["remaining_cash"], "reservation remaining_cash")
        != projection.remaining_cash
        or _require_decimal(
            row["initial_buy_exposure"],
            "reservation initial_buy_exposure",
        )
        != projection.initial_buy_exposure
        or _require_decimal(
            row["remaining_buy_exposure"],
            "reservation remaining_buy_exposure",
        )
        != projection.remaining_buy_exposure
        or persisted_released_at != projection.released_at
    ):
        raise BatchRiskFactConflict(
            "reservation mutable head disagrees with append-only release history"
        )
    return projection, history


def verify_batch_reservation_heads(connection: Connection) -> None:
    """Authenticate every reservation head for database-readiness checks."""

    rows = tuple(
        connection.execute(
            sa.select(phase2_batch_reservations).order_by(
                phase2_batch_reservations.c.reservation_id
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        decision = load_batch_risk_decision(
            connection,
            _require_text(row["parent_decision_id"], "reservation parent_decision_id"),
        )
        if decision is None or decision.reservation is None:
            raise BatchRiskFactConflict("reservation lacks its complete approved parent decision")
        _authenticate_reservation_head(connection, row, decision.reservation)


def _decision_for_batch(
    connection: Connection,
    intent_batch_id: str,
) -> tuple[BatchRiskDecision, RowMapping] | None:
    row = (
        connection.execute(
            sa.select(phase2_batch_decisions).where(
                phase2_batch_decisions.c.intent_batch_id == intent_batch_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    decision = load_batch_risk_decision(
        connection,
        _require_text(row["decision_id"], "decision_id"),
    )
    if decision is None:  # pragma: no cover - selected immediately above
        raise BatchRiskFactConflict("persisted batch decision disappeared during transaction")
    return decision, row


def _account_observation_rows(
    connection: Connection,
    account_id: str,
) -> tuple[RowMapping, ...]:
    return tuple(
        connection.execute(
            sa.select(
                phase2_batch_decisions.c.decision_id,
                phase2_batch_decisions.c.account_observation_sequence,
            )
            .where(phase2_batch_decisions.c.account_id == account_id)
            .order_by(phase2_batch_decisions.c.account_observation_sequence)
        )
        .mappings()
        .all()
    )


def _next_account_observation_sequence(
    connection: Connection,
    account_id: str,
) -> int:
    """Allocate the next sequence while the caller holds the account lease lock."""

    rows = _account_observation_rows(connection, account_id)
    sequences = tuple(
        _require_int(row["account_observation_sequence"], "account observation sequence")
        for row in rows
    )
    if sequences != tuple(range(1, len(sequences) + 1)):
        raise BatchRiskFactConflict("account decision observation sequence is not contiguous")
    return len(sequences) + 1


class SqlBatchRiskRepository:
    """Serialize one account's durable batch capacity under its lease-head lock."""

    def __init__(
        self,
        *,
        engine: Engine,
        authority: BatchRiskAuthority,
        coordinator: SqlAccountFenceValidator,
    ) -> None:
        if not callable(getattr(authority.snapshots, "transact", None)):
            raise BatchRiskFactConflict(
                "durable batch risk requires transactional snapshot authority"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise BatchRiskFactConflict("durable batch risk requires a SQL fence validator")
        self._engine = engine
        self._authority = authority
        self._coordinator = coordinator

    def authorize(
        self,
        batch: OrderIntentBatch,
        target: TargetPortfolio,
        fence: AccountFence,
    ) -> BatchRiskDecision:
        """Publish an all-or-none decision and all holds in one SQL transaction."""

        if type(batch) is not OrderIntentBatch:
            raise BatchRiskFactConflict("durable authorization requires an exact intent batch")
        if type(target) is not TargetPortfolio:
            raise BatchRiskFactConflict("durable authorization requires exact target evidence")
        if type(fence) is not AccountFence:
            raise BatchRiskFactConflict("durable authorization requires an exact account fence")
        if batch.target_id != target.target_id or batch.target_sha256 != target.semantic_sha256:
            raise BatchRiskFactConflict("intent batch does not bind the target evidence")

        snapshots = cast(_SnapshotTransactions, self._authority.snapshots)

        def operation(snapshot: VersionedBatchRiskSnapshot) -> BatchRiskDecision:
            if type(snapshot) is not VersionedBatchRiskSnapshot:
                raise BatchRiskFactConflict(
                    "durable batch snapshot authority returned a non-canonical value"
                )
            snapshot._validate()
            if snapshot.account_id != fence.account_id:
                raise BatchRiskFactConflict("risk snapshot and coordinator fence accounts differ")
            evaluated_at = self._authority.evaluation_clock.now()
            try:
                require_utc(evaluated_at, "durable batch evaluated_at")
            except ValueError as error:
                raise BatchRiskFactConflict(str(error)) from error
            with self._engine.begin() as connection:
                receipt = self._coordinator.revalidate_in_transaction(
                    connection,
                    fence,
                    checked_at=evaluated_at,
                )
                if type(receipt) is not AccountFenceReceipt:
                    raise BatchRiskFactConflict(
                        "SQL fence validator returned a non-canonical receipt"
                    )
                receipt._validate()
                if receipt.fence != fence or receipt.validated_at != evaluated_at:
                    raise BatchRiskFactConflict(
                        "SQL fence receipt does not bind the requested fence and instant"
                    )
                prior = _decision_for_batch(connection, batch.intent_batch_id)
                if prior is not None:
                    decision, row = prior
                    if decision.intent_batch_sha256 != batch.semantic_sha256:
                        raise BatchRiskFactConflict("intent batch IDs are immutable")
                    if (
                        decision.account_id != snapshot.account_id
                        or decision.snapshot_version != snapshot.version
                        or decision.snapshot_sha256 != snapshot.semantic_sha256
                        or decision.policy_sha256 != self._authority.limits.semantic_sha256
                    ):
                        raise BatchRiskFactConflict(
                            "intent batch decision belongs to different risk evidence"
                        )
                    if (
                        row["fencing_generation"] != receipt.fence.fencing_generation
                        or row["fence_sha256"] != receipt.fence.semantic_sha256
                    ):
                        raise BatchRiskFactConflict(
                            "intent batch decision belongs to a different coordinator fence"
                        )
                    expected_members = tuple(
                        (intent.intent_id, intent_payload_hash(intent)) for intent in batch.intents
                    )
                    if _decode_batch_members(connection, decision.decision_id) != expected_members:
                        raise BatchRiskFactConflict(
                            "intent batch members conflict with durable identity evidence"
                        )
                    return decision

                account_observation_sequence = _next_account_observation_sequence(
                    connection,
                    snapshot.account_id,
                )
                active_capacity = _active_capacity_universe(
                    connection,
                    snapshot.account_id,
                    as_of=evaluated_at,
                )
                decision = evaluate_batch_risk_decision(
                    batch=batch,
                    target=target,
                    snapshot=snapshot,
                    limits=self._authority.limits,
                    active_capacity=active_capacity,
                    evaluated_at=evaluated_at,
                )
                try:
                    connection.execute(
                        sa.insert(phase2_batch_decisions).values(
                            **_decision_values(
                                decision,
                                receipt,
                                active_capacity,
                                account_observation_sequence,
                            )
                        )
                    )
                    member_values = _batch_member_values(decision, batch)
                    if member_values:
                        connection.execute(sa.insert(phase2_batch_members), member_values)
                    if decision.reservation is not None:
                        connection.execute(
                            sa.insert(phase2_batch_reservations).values(
                                **_reservation_values(
                                    decision.reservation,
                                    receipt,
                                    expires_at=decision.expires_at,
                                )
                            )
                        )
                        connection.execute(
                            sa.insert(phase2_batch_authorizations),
                            [
                                _authorization_values(authorization, receipt)
                                for authorization in decision.authorizations
                            ],
                        )
                except IntegrityError as error:
                    raise BatchRiskFactConflict(
                        "durable batch facts conflict with existing immutable identities"
                    ) from error
                persisted = load_batch_risk_decision(connection, decision.decision_id)
                if persisted != decision:
                    raise BatchRiskFactConflict(
                        "SQL storage did not preserve the exact batch decision"
                    )
                return decision

        return snapshots.transact(operation)

    def get_batch(self, decision_id: str) -> BatchRiskDecision | None:
        with self._engine.connect() as connection:
            return load_batch_risk_decision(connection, decision_id)

    def decision_for_batch(self, intent_batch_id: str) -> BatchRiskDecision | None:
        with self._engine.connect() as connection:
            found = _decision_for_batch(connection, intent_batch_id)
            return None if found is None else found[0]

    def active_reservations(self, account_id: str) -> tuple[BatchRiskReservation, ...]:
        with self._engine.connect() as connection:
            return _active_reservations(connection, account_id)

    def active_capacity(self, account_id: str) -> ActiveCapacityUniverse:
        """Return the exact authenticated remaining-capacity universe for risk."""

        with self._engine.connect() as connection:
            return _active_capacity_universe(connection, account_id)
