"""Append-only finality facts and conservative reservation-capacity projections.

This module is a pure domain boundary.  Callers remain responsible for proving
that supplied parent-attempt snapshots, accounting facts, reconciliation
snapshots, and simulation horizons are complete durable observations.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from packages.domain.batch_risk import BatchRiskAuthorization, BatchRiskReservation
from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decimal_math import (
    exact_decimal_add,
    exact_decimal_multiply,
    exact_decimal_subtract,
    exact_decimal_sum,
)
from packages.domain.identifiers import canonical_id
from packages.domain.models import Side, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    CanonicalOrderState,
    CanonicalOrderStatus,
    reduce_order_lifecycle,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
    UnknownSubmissionResolution,
    reduce_submission_attempt,
)

RESERVATION_LIFECYCLE_CONTRACT_VERSION = "phase2-reservation-lifecycle-v1"


class ReservationLifecycleError(ValueError):
    """Reservation finality evidence is malformed or unsafe."""


class ReservationReleaseConflict(ReservationLifecycleError):
    """An immutable release identity or capacity fact conflicts."""


class ReservationReleaseReason(StrEnum):
    """The complete release-reason vocabulary persisted by the Phase 2 schema."""

    APPROVAL_EXPIRED_UNSENT = "approval_expired_unsent"
    BROKER_REJECTED = "broker_rejected"
    EXECUTION_ACCOUNTED = "execution_accounted"
    RECONCILED_TERMINAL = "reconciled_terminal"
    SIMULATION_HORIZON_FINAL = "simulation_horizon_final"


class ReservationCapacityState(StrEnum):
    ACTIVE = "active"
    PARTIALLY_RELEASED = "partially_released"
    FROZEN = "frozen"
    RELEASED = "released"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 256) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ReservationLifecycleError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise ReservationLifecycleError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReservationLifecycleError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_independent_source(
    source_sha256: str,
    local_sha256s: tuple[str, ...],
    message: str,
) -> None:
    _require_sha256(source_sha256, "release source digest")
    if source_sha256 in local_sha256s:
        raise ReservationLifecycleError(message)


def _require_utc(value: datetime, field_name: str) -> None:
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise ReservationLifecycleError(str(error)) from error


def _amount(value: Decimal, field_name: str, *, whole: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise ReservationLifecycleError(f"{field_name} must be a finite non-negative Decimal")
    if whole and value != value.to_integral_value():
        raise ReservationLifecycleError(f"{field_name} must be a whole number of shares")
    try:
        return canonical_persisted_decimal(value, field_name)
    except (TypeError, ValueError) as error:
        raise ReservationLifecycleError(str(error)) from error


@dataclass(frozen=True, slots=True, init=False)
class ReservationReleaseFact:
    """One immutable capacity delta authorized by exact external finality evidence."""

    release_event_id: str
    sequence_number: int
    previous_release_sha256: str | None
    reservation_id: str
    reservation_sha256: str
    parent_decision_id: str
    authorization_id: str
    authorization_sha256: str
    order_id: str | None
    attempt_id: str | None
    order_event_id: str | None
    reason: ReservationReleaseReason
    finality_reference: str
    source_sha256: str
    attempt_sha256: str | None
    order_state_sha256: str | None
    order_event_sha256: str | None
    execution_id: str | None
    execution_revision: int | None
    execution_head_quantity: Decimal | None
    accounted_quantity: Decimal | None
    released_cash: Decimal
    released_buy_exposure: Decimal
    released_sell_quantity: Decimal
    occurred_at: datetime
    recorded_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ReservationReleaseFact must be created by a finality reducer")

    def _validate(self) -> None:
        for value, field_name, maximum in (
            (self.release_event_id, "release event ID", 64),
            (self.reservation_id, "release reservation ID", 64),
            (self.parent_decision_id, "release parent decision ID", 64),
            (self.authorization_id, "release authorization ID", 64),
            (self.finality_reference, "release finality reference", 256),
        ):
            _require_text(value, field_name, maximum=maximum)
        for value, field_name in (
            (self.reservation_sha256, "release reservation digest"),
            (self.authorization_sha256, "release authorization digest"),
            (self.source_sha256, "release source digest"),
        ):
            _require_sha256(value, field_name)
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise ReservationLifecycleError("release sequence number must be positive")
        _require_optional_sha256(self.previous_release_sha256, "previous release digest")
        if self.sequence_number == 1:
            if self.previous_release_sha256 is not None:
                raise ReservationLifecycleError("first release cannot name a predecessor")
        elif self.previous_release_sha256 is None:
            raise ReservationLifecycleError("successor release requires its predecessor digest")
        if type(self.reason) is not ReservationReleaseReason:
            raise ReservationLifecycleError("release reason must use the exact schema vocabulary")
        for optional_value, optional_field_name, maximum in (
            (self.order_id, "release order ID", 64),
            (self.attempt_id, "release attempt ID", 64),
            (self.order_event_id, "release order event ID", 128),
            (self.execution_id, "release execution ID", 128),
        ):
            if optional_value is not None:
                _require_text(optional_value, optional_field_name, maximum=maximum)
        for optional_digest, optional_digest_name in (
            (self.attempt_sha256, "release attempt digest"),
            (self.order_state_sha256, "release order-state digest"),
            (self.order_event_sha256, "release order-event digest"),
        ):
            _require_optional_sha256(optional_digest, optional_digest_name)
        self._validate_evidence_shape()
        released_cash = _amount(self.released_cash, "released cash")
        released_buy_exposure = _amount(
            self.released_buy_exposure,
            "released buy exposure",
        )
        released_sell_quantity = _amount(
            self.released_sell_quantity,
            "released sell quantity",
            whole=True,
        )
        if not any(
            value > 0
            for value in (
                released_cash,
                released_buy_exposure,
                released_sell_quantity,
            )
        ):
            raise ReservationLifecycleError("a release fact must free positive capacity")
        _require_utc(self.occurred_at, "release occurred_at")
        _require_utc(self.recorded_at, "release recorded_at")
        if self.recorded_at < self.occurred_at:
            raise ReservationLifecycleError("release cannot be recorded before finality occurred")
        if self.release_event_id != self._expected_event_id():
            raise ReservationReleaseConflict("release event ID is not canonically derived")

    def _validate_evidence_shape(self) -> None:
        attempt_pair = (self.attempt_id, self.attempt_sha256)
        order_pair = (self.order_id, self.order_state_sha256)
        event_pair = (self.order_event_id, self.order_event_sha256)
        if any(value is None for value in attempt_pair) and any(
            value is not None for value in attempt_pair
        ):
            raise ReservationLifecycleError(
                "release attempt identity and digest must travel together"
            )
        if any(value is None for value in order_pair) and any(
            value is not None for value in order_pair
        ):
            raise ReservationLifecycleError(
                "release order identity and state digest must travel together"
            )
        if any(value is None for value in event_pair) and any(
            value is not None for value in event_pair
        ):
            raise ReservationLifecycleError(
                "release event identity and digest must travel together"
            )
        if self.order_event_id is not None and self.order_id is None:
            raise ReservationLifecycleError("order-event finality requires its logical order")

        execution_values = (
            self.execution_id,
            self.execution_revision,
            self.execution_head_quantity,
            self.accounted_quantity,
        )
        if self.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED:
            if self.order_id is None or self.attempt_id is None or self.order_event_id is None:
                raise ReservationLifecycleError(
                    "execution release requires order, attempt, and order-event evidence"
                )
            if any(value is None for value in execution_values):
                raise ReservationLifecycleError(
                    "execution release requires exact revision evidence"
                )
            if type(self.execution_revision) is not int or self.execution_revision <= 0:
                raise ReservationLifecycleError("execution revision must be positive")
            assert self.execution_head_quantity is not None
            assert self.accounted_quantity is not None
            if (
                _amount(
                    self.execution_head_quantity,
                    "execution head quantity",
                    whole=True,
                )
                <= 0
            ):
                raise ReservationLifecycleError("execution head quantity must be positive")
            if _amount(self.accounted_quantity, "accounted quantity", whole=True) <= 0:
                raise ReservationLifecycleError("accounted quantity must be positive")
            return
        if any(value is not None for value in execution_values):
            raise ReservationLifecycleError("non-execution release cannot carry execution deltas")

        if self.reason is ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT:
            if any(
                value is not None
                for value in (
                    self.order_id,
                    self.attempt_id,
                    self.order_event_id,
                )
            ):
                raise ReservationLifecycleError(
                    "unsent approval expiry cannot carry sent-order evidence"
                )
        elif self.reason is ReservationReleaseReason.BROKER_REJECTED:
            if self.order_id is None or self.attempt_id is None or self.order_event_id is None:
                raise ReservationLifecycleError(
                    "broker rejection requires order, attempt, and rejection-event evidence"
                )
        elif self.reason is ReservationReleaseReason.RECONCILED_TERMINAL:
            if self.attempt_id is None:
                raise ReservationLifecycleError("reconciled terminal release requires an attempt")
        elif self.reason is ReservationReleaseReason.SIMULATION_HORIZON_FINAL and (
            self.order_id is None or self.attempt_id is None
        ):
            raise ReservationLifecycleError(
                "simulation finality requires exact order and attempt evidence"
            )

    def _expected_event_id(self) -> str:
        return canonical_id(
            "reservation-release",
            self.reservation_id,
            self.sequence_number,
            self.previous_release_sha256,
            self.authorization_id,
            self.reason.value,
            self.finality_reference,
            self.source_sha256,
            self.order_id,
            self.attempt_id,
            self.order_event_id,
            self.occurred_at,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            RESERVATION_LIFECYCLE_CONTRACT_VERSION,
            "release_fact",
            self.release_event_id,
            self.sequence_number,
            self.previous_release_sha256,
            self.reservation_id,
            self.reservation_sha256,
            self.parent_decision_id,
            self.authorization_id,
            self.authorization_sha256,
            self.order_id,
            self.attempt_id,
            self.order_event_id,
            self.reason.value,
            self.finality_reference,
            self.source_sha256,
            self.attempt_sha256,
            self.order_state_sha256,
            self.order_event_sha256,
            self.execution_id,
            self.execution_revision,
            self.execution_head_quantity,
            self.accounted_quantity,
            self.released_cash,
            self.released_buy_exposure,
            self.released_sell_quantity,
            self.occurred_at,
            self.recorded_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class AuthorizationCapacityProjection:
    authorization_id: str
    instrument_id: str
    side: Side
    initial_cash: Decimal
    initial_buy_exposure: Decimal
    initial_sell_quantity: Decimal
    released_cash: Decimal
    released_buy_exposure: Decimal
    released_sell_quantity: Decimal
    remaining_cash: Decimal
    remaining_buy_exposure: Decimal
    remaining_sell_quantity: Decimal
    release_event_ids: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AuthorizationCapacityProjection must be reducer-produced")

    @property
    def fully_released(self) -> bool:
        return (
            self.remaining_cash == 0
            and self.remaining_buy_exposure == 0
            and self.remaining_sell_quantity == 0
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                RESERVATION_LIFECYCLE_CONTRACT_VERSION,
                "authorization_capacity",
                self.authorization_id,
                self.instrument_id,
                self.side.value,
                self.initial_cash,
                self.initial_buy_exposure,
                self.initial_sell_quantity,
                self.released_cash,
                self.released_buy_exposure,
                self.released_sell_quantity,
                self.remaining_cash,
                self.remaining_buy_exposure,
                self.remaining_sell_quantity,
                self.release_event_ids,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class InstrumentSellCapacityProjection:
    instrument_id: str
    initial_quantity: Decimal
    released_quantity: Decimal
    remaining_quantity: Decimal

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("InstrumentSellCapacityProjection must be reducer-produced")


@dataclass(frozen=True, slots=True, init=False)
class ReservationCapacityProjection:
    reservation_id: str
    reservation_sha256: str
    parent_decision_id: str
    state: ReservationCapacityState
    authorization_count: int
    remaining_authorization_count: int
    initial_cash: Decimal
    released_cash: Decimal
    remaining_cash: Decimal
    initial_buy_exposure: Decimal
    released_buy_exposure: Decimal
    remaining_buy_exposure: Decimal
    authorizations: tuple[AuthorizationCapacityProjection, ...]
    sell_capacity: tuple[InstrumentSellCapacityProjection, ...]
    release_event_ids: tuple[str, ...]
    unknown_authorization_ids: tuple[str, ...]
    released_at: datetime | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ReservationCapacityProjection must be reducer-produced")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                RESERVATION_LIFECYCLE_CONTRACT_VERSION,
                "reservation_capacity",
                self.reservation_id,
                self.reservation_sha256,
                self.parent_decision_id,
                self.state.value,
                self.authorization_count,
                self.remaining_authorization_count,
                self.initial_cash,
                self.released_cash,
                self.remaining_cash,
                self.initial_buy_exposure,
                self.released_buy_exposure,
                self.remaining_buy_exposure,
                tuple(item.semantic_sha256 for item in self.authorizations),
                tuple(
                    (
                        item.instrument_id,
                        item.initial_quantity,
                        item.released_quantity,
                        item.remaining_quantity,
                    )
                    for item in self.sell_capacity
                ),
                self.release_event_ids,
                self.unknown_authorization_ids,
                self.released_at,
            )
        )


@dataclass(slots=True)
class _RunningAuthorizationCapacity:
    authorization: BatchRiskAuthorization
    released_cash: Decimal = Decimal(0)
    released_buy_exposure: Decimal = Decimal(0)
    released_sell_quantity: Decimal = Decimal(0)
    release_event_ids: list[str] = field(default_factory=list)


def _require_reservation(reservation: BatchRiskReservation) -> None:
    if type(reservation) is not BatchRiskReservation:
        raise ReservationLifecycleError("reservation reducer requires an exact reservation")
    try:
        reservation.__post_init__()
    except ValueError as error:
        raise ReservationReleaseConflict(str(error)) from error


def _authorization_for_release(
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
) -> BatchRiskAuthorization:
    _require_reservation(reservation)
    if type(authorization) is not BatchRiskAuthorization:
        raise ReservationLifecycleError("release requires an exact authorization")
    try:
        authorization.__post_init__()
    except ValueError as error:
        raise ReservationReleaseConflict(str(error)) from error
    matches = tuple(
        item for item in reservation.authorizations if item.decision_id == authorization.decision_id
    )
    if len(matches) != 1 or matches[0] != authorization:
        raise ReservationReleaseConflict(
            "release authorization does not exactly belong to its reservation"
        )
    return matches[0]


def _remaining(
    initial: Decimal,
    released: Decimal,
    field_name: str,
) -> Decimal:
    value = exact_decimal_subtract(initial, released)
    if value < 0:
        raise ReservationReleaseConflict(f"released {field_name} exceeds reserved capacity")
    return value


def _new_projection_value(
    projection_type: type[object],
    values: tuple[tuple[str, object], ...],
) -> object:
    projection = object.__new__(projection_type)
    for field_name, value in values:
        object.__setattr__(projection, field_name, value)
    return projection


def project_reservation_capacity(
    reservation: BatchRiskReservation,
    release_facts: tuple[ReservationReleaseFact, ...] = (),
    *,
    unknown_authorization_ids: frozenset[str] = frozenset(),
) -> ReservationCapacityProjection:
    """Rebuild remaining capacity from one exact reservation and its release log."""

    _require_reservation(reservation)
    if type(release_facts) is not tuple or any(
        type(fact) is not ReservationReleaseFact for fact in release_facts
    ):
        raise ReservationLifecycleError("release history must be an immutable tuple of exact facts")
    if type(unknown_authorization_ids) is not frozenset:
        raise ReservationLifecycleError("UNKNOWN authorization IDs must be a frozenset")
    authorization_by_id = {
        authorization.decision_id: authorization for authorization in reservation.authorizations
    }
    for authorization_id in unknown_authorization_ids:
        _require_text(authorization_id, "UNKNOWN authorization ID", maximum=64)
        if authorization_id not in authorization_by_id:
            raise ReservationReleaseConflict(
                "UNKNOWN authorization belongs to a different reservation"
            )

    running = {
        authorization.decision_id: _RunningAuthorizationCapacity(authorization)
        for authorization in reservation.authorizations
    }
    seen_event_ids: set[str] = set()
    seen_semantics: set[str] = set()
    execution_heads: dict[tuple[str, str], tuple[int, Decimal]] = {}
    execution_totals: dict[str, Decimal] = {}
    previous: ReservationReleaseFact | None = None
    for sequence_number, fact in enumerate(release_facts, start=1):
        fact._validate()
        if fact.sequence_number != sequence_number:
            raise ReservationLifecycleError("release sequence must be contiguous from one")
        expected_previous = None if previous is None else previous.semantic_sha256
        if fact.previous_release_sha256 != expected_previous:
            raise ReservationReleaseConflict("release fact does not chain to its exact predecessor")
        if fact.release_event_id in seen_event_ids:
            raise ReservationReleaseConflict("release event identity is reused")
        if fact.semantic_sha256 in seen_semantics:
            raise ReservationReleaseConflict("release fact semantics are duplicated")
        seen_event_ids.add(fact.release_event_id)
        seen_semantics.add(fact.semantic_sha256)
        if (
            fact.reservation_id != reservation.reservation_id
            or fact.reservation_sha256 != reservation.semantic_sha256
            or fact.parent_decision_id != reservation.parent_decision_id
        ):
            raise ReservationReleaseConflict("release fact belongs to another reservation")
        authorization = authorization_by_id.get(fact.authorization_id)
        if authorization is None:
            raise ReservationReleaseConflict("release fact names an unknown authorization")
        if fact.authorization_sha256 != authorization.semantic_sha256:
            raise ReservationReleaseConflict("release fact changed its authorization evidence")
        if fact.occurred_at < authorization.evaluated_at:
            raise ReservationLifecycleError("release finality cannot predate risk evaluation")
        capacity = running[authorization.decision_id]
        current_cash = _remaining(
            authorization.reserved_cash,
            capacity.released_cash,
            "cash",
        )
        current_exposure = _remaining(
            authorization.reserved_buy_exposure,
            capacity.released_buy_exposure,
            "buy exposure",
        )
        current_sell = _remaining(
            authorization.reserved_sell_quantity,
            capacity.released_sell_quantity,
            "sell shares",
        )

        if fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED:
            assert fact.execution_id is not None
            assert fact.execution_revision is not None
            assert fact.execution_head_quantity is not None
            assert fact.accounted_quantity is not None
            key = (authorization.decision_id, fact.execution_id)
            prior_revision, prior_quantity = execution_heads.get(key, (0, Decimal(0)))
            if fact.execution_revision <= prior_revision:
                raise ReservationReleaseConflict(
                    "execution release revision does not advance its accounted head"
                )
            expected_head = exact_decimal_add(prior_quantity, fact.accounted_quantity)
            if fact.execution_head_quantity != expected_head:
                raise ReservationReleaseConflict(
                    "execution correction does not establish a monotone release delta"
                )
            accounted_total = exact_decimal_add(
                execution_totals.get(authorization.decision_id, Decimal(0)),
                fact.accounted_quantity,
            )
            if accounted_total > authorization.quantity:
                raise ReservationReleaseConflict(
                    "accounted execution quantities exceed the authorized order"
                )
            expected_exposure = (
                exact_decimal_multiply(
                    fact.accounted_quantity,
                    authorization.maximum_execution_price,
                )
                if authorization.side is Side.BUY
                else Decimal(0)
            )
            expected_cash = expected_exposure
            expected_sell = (
                fact.accounted_quantity if authorization.side is Side.SELL else Decimal(0)
            )
            if (
                fact.released_cash != expected_cash
                or fact.released_buy_exposure != expected_exposure
                or fact.released_sell_quantity != expected_sell
            ):
                raise ReservationReleaseConflict(
                    "execution release does not match its conservative quantity delta"
                )
            execution_heads[key] = (fact.execution_revision, fact.execution_head_quantity)
            execution_totals[authorization.decision_id] = accounted_total
        else:
            if (
                fact.reason
                in (
                    ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT,
                    ReservationReleaseReason.BROKER_REJECTED,
                )
                and capacity.release_event_ids
            ):
                raise ReservationReleaseConflict(
                    "unsent expiry or broker rejection cannot follow an economic release"
                )
            if (
                fact.released_cash != current_cash
                or fact.released_buy_exposure != current_exposure
                or fact.released_sell_quantity != current_sell
            ):
                raise ReservationReleaseConflict(
                    "terminal finality must release the exact remaining child capacity"
                )

        next_cash = exact_decimal_add(capacity.released_cash, fact.released_cash)
        next_exposure = exact_decimal_add(
            capacity.released_buy_exposure,
            fact.released_buy_exposure,
        )
        next_sell = exact_decimal_add(
            capacity.released_sell_quantity,
            fact.released_sell_quantity,
        )
        if (
            next_cash > authorization.reserved_cash
            or next_exposure > authorization.reserved_buy_exposure
            or next_sell > authorization.reserved_sell_quantity
        ):
            raise ReservationReleaseConflict("release history exceeds its child reservation")
        capacity.released_cash = next_cash
        capacity.released_buy_exposure = next_exposure
        capacity.released_sell_quantity = next_sell
        capacity.release_event_ids.append(fact.release_event_id)
        previous = fact

    authorization_projections: list[AuthorizationCapacityProjection] = []
    sell_projections: list[InstrumentSellCapacityProjection] = []
    for authorization in reservation.authorizations:
        capacity = running[authorization.decision_id]
        if authorization.decision_id in unknown_authorization_ids and capacity.release_event_ids:
            raise ReservationReleaseConflict(
                "an UNKNOWN authorization cannot authorize capacity release"
            )
        remaining_cash = _remaining(
            authorization.reserved_cash,
            capacity.released_cash,
            "cash",
        )
        remaining_exposure = _remaining(
            authorization.reserved_buy_exposure,
            capacity.released_buy_exposure,
            "buy exposure",
        )
        remaining_sell = _remaining(
            authorization.reserved_sell_quantity,
            capacity.released_sell_quantity,
            "sell shares",
        )
        child = _new_projection_value(
            AuthorizationCapacityProjection,
            (
                ("authorization_id", authorization.decision_id),
                ("instrument_id", authorization.instrument_id),
                ("side", authorization.side),
                ("initial_cash", authorization.reserved_cash),
                ("initial_buy_exposure", authorization.reserved_buy_exposure),
                ("initial_sell_quantity", authorization.reserved_sell_quantity),
                ("released_cash", capacity.released_cash),
                ("released_buy_exposure", capacity.released_buy_exposure),
                ("released_sell_quantity", capacity.released_sell_quantity),
                ("remaining_cash", remaining_cash),
                ("remaining_buy_exposure", remaining_exposure),
                ("remaining_sell_quantity", remaining_sell),
                ("release_event_ids", tuple(capacity.release_event_ids)),
            ),
        )
        assert isinstance(child, AuthorizationCapacityProjection)
        authorization_projections.append(child)
        if authorization.reserved_sell_quantity > 0:
            sell = _new_projection_value(
                InstrumentSellCapacityProjection,
                (
                    ("instrument_id", authorization.instrument_id),
                    ("initial_quantity", authorization.reserved_sell_quantity),
                    ("released_quantity", capacity.released_sell_quantity),
                    ("remaining_quantity", remaining_sell),
                ),
            )
            assert isinstance(sell, InstrumentSellCapacityProjection)
            sell_projections.append(sell)

    child_tuple = tuple(authorization_projections)
    initial_cash = reservation.reserved_cash
    released_cash = exact_decimal_sum(item.released_cash for item in child_tuple)
    remaining_cash = exact_decimal_sum(item.remaining_cash for item in child_tuple)
    initial_exposure = reservation.reserved_buy_exposure
    released_exposure = exact_decimal_sum(item.released_buy_exposure for item in child_tuple)
    remaining_exposure = exact_decimal_sum(item.remaining_buy_exposure for item in child_tuple)
    if exact_decimal_add(released_cash, remaining_cash) != initial_cash:
        raise ReservationReleaseConflict("reservation cash is not conserved")
    if exact_decimal_add(released_exposure, remaining_exposure) != initial_exposure:
        raise ReservationReleaseConflict("reservation buy exposure is not conserved")
    remaining_count = sum(not item.fully_released for item in child_tuple)
    if unknown_authorization_ids:
        state = ReservationCapacityState.FROZEN
    elif remaining_count == 0:
        state = ReservationCapacityState.RELEASED
    elif release_facts:
        state = ReservationCapacityState.PARTIALLY_RELEASED
    else:
        state = ReservationCapacityState.ACTIVE
    released_at = (
        max(fact.recorded_at for fact in release_facts)
        if state is ReservationCapacityState.RELEASED
        else None
    )
    projection = _new_projection_value(
        ReservationCapacityProjection,
        (
            ("reservation_id", reservation.reservation_id),
            ("reservation_sha256", reservation.semantic_sha256),
            ("parent_decision_id", reservation.parent_decision_id),
            ("state", state),
            ("authorization_count", len(child_tuple)),
            ("remaining_authorization_count", remaining_count),
            ("initial_cash", initial_cash),
            ("released_cash", released_cash),
            ("remaining_cash", remaining_cash),
            ("initial_buy_exposure", initial_exposure),
            ("released_buy_exposure", released_exposure),
            ("remaining_buy_exposure", remaining_exposure),
            ("authorizations", child_tuple),
            ("sell_capacity", tuple(sell_projections)),
            ("release_event_ids", tuple(fact.release_event_id for fact in release_facts)),
            ("unknown_authorization_ids", tuple(sorted(unknown_authorization_ids))),
            ("released_at", released_at),
        ),
    )
    assert isinstance(projection, ReservationCapacityProjection)
    return projection


def _canonical_attempt(attempt: CanonicalSubmissionAttempt) -> None:
    if type(attempt) is not CanonicalSubmissionAttempt:
        raise ReservationLifecycleError("release requires an exact submission attempt")
    if reduce_submission_attempt(attempt.preparation, attempt.events) != attempt:
        raise ReservationReleaseConflict("release attempt is not reducer-produced")


def _canonical_order_state(order_state: CanonicalOrderState) -> None:
    if type(order_state) is not CanonicalOrderState:
        raise ReservationLifecycleError("release requires an exact canonical order state")
    rebuilt = reduce_order_lifecycle(
        submission=order_state.submission,
        broker_events=order_state.broker_events,
        cancel_request=order_state.cancel_request,
    )
    if rebuilt != order_state:
        raise ReservationReleaseConflict("release order state is not reducer-produced")


def _bind_attempt(
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
) -> None:
    _canonical_attempt(attempt)
    preparation = attempt.preparation
    if (
        preparation.parent_decision_id != reservation.parent_decision_id
        or preparation.reservation_id != reservation.reservation_id
        or preparation.authorization_id != authorization.decision_id
        or preparation.authorization_sha256 != authorization.semantic_sha256
    ):
        raise ReservationReleaseConflict(
            "submission attempt is not bound to the exact reservation child"
        )


def _bind_order(
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
) -> None:
    _canonical_order_state(order_state)
    submission = order_state.submission
    if (
        submission.order_id != attempt.order_id
        or submission.submission_attempt_id != attempt.attempt_id
        or submission.risk_decision_id != authorization.decision_id
        or submission.intent != attempt.preparation.intent
        or submission.intent.intent_id != authorization.intent_id
        or intent_payload_hash(submission.intent) != authorization.intent_payload_hash
    ):
        raise ReservationReleaseConflict(
            "logical order is not bound to the exact attempt and authorization"
        )
    if (
        attempt.broker_order_id is not None
        and order_state.broker_order_id is not None
        and attempt.broker_order_id != order_state.broker_order_id
    ):
        raise ReservationReleaseConflict("attempt and order disagree on broker identity")


def _bind_order_event(
    order_state: CanonicalOrderState,
    order_event: BrokerOrderEvent,
    *,
    require_last: bool,
) -> None:
    if type(order_event) is not BrokerOrderEvent:
        raise ReservationLifecycleError("release requires an exact broker order event")
    order_event.__post_init__()
    matches = tuple(
        event for event in order_state.broker_events if event.event_id == order_event.event_id
    )
    if len(matches) != 1 or matches[0] != order_event:
        raise ReservationReleaseConflict("release event is absent from the exact order state")
    if require_last and order_state.broker_events[-1] != order_event:
        raise ReservationReleaseConflict("terminal release requires the latest broker event")


def _require_known_broker_effect(attempt: CanonicalSubmissionAttempt) -> None:
    if attempt.state in (
        SubmissionAttemptState.PENDING,
        SubmissionAttemptState.IN_FLIGHT,
        SubmissionAttemptState.UNKNOWN,
    ):
        raise ReservationLifecycleError(
            "pending, in-flight, or UNKNOWN submission cannot authorize release"
        )
    if (
        attempt.state is SubmissionAttemptState.RESOLVED
        and attempt.resolution is UnknownSubmissionResolution.NOT_SUBMITTED
    ):
        raise ReservationLifecycleError("confirmed broker absence has no sent order")


def _child_projection(
    projection: ReservationCapacityProjection,
    authorization_id: str,
) -> AuthorizationCapacityProjection:
    matches = tuple(
        child for child in projection.authorizations if child.authorization_id == authorization_id
    )
    if len(matches) != 1:
        raise ReservationReleaseConflict("reservation projection lost its exact child")
    return matches[0]


def _terminal_amounts(
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    prior_releases: tuple[ReservationReleaseFact, ...],
) -> tuple[Decimal, Decimal, Decimal]:
    projection = project_reservation_capacity(reservation, prior_releases)
    child = _child_projection(projection, authorization.decision_id)
    if child.fully_released:
        raise ReservationReleaseConflict("authorization capacity is already fully released")
    return (
        child.remaining_cash,
        child.remaining_buy_exposure,
        child.remaining_sell_quantity,
    )


def _new_release_fact(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    prior_releases: tuple[ReservationReleaseFact, ...],
    reason: ReservationReleaseReason,
    finality_reference: str,
    source_sha256: str,
    occurred_at: datetime,
    recorded_at: datetime,
    released_cash: Decimal,
    released_buy_exposure: Decimal,
    released_sell_quantity: Decimal,
    attempt: CanonicalSubmissionAttempt | None = None,
    order_state: CanonicalOrderState | None = None,
    order_event: BrokerOrderEvent | None = None,
    execution_id: str | None = None,
    execution_revision: int | None = None,
    execution_head_quantity: Decimal | None = None,
    accounted_quantity: Decimal | None = None,
) -> ReservationReleaseFact:
    _authorization_for_release(reservation, authorization)
    project_reservation_capacity(reservation, prior_releases)
    _require_text(finality_reference, "release finality reference", maximum=256)
    _require_sha256(source_sha256, "release source digest")
    _require_utc(occurred_at, "release occurred_at")
    _require_utc(recorded_at, "release recorded_at")
    sequence_number = len(prior_releases) + 1
    previous_sha256 = None if not prior_releases else prior_releases[-1].semantic_sha256
    order_id = None if order_state is None else order_state.submission.order_id
    attempt_id = None if attempt is None else attempt.attempt_id
    order_event_id = None if order_event is None else order_event.event_id
    release_event_id = canonical_id(
        "reservation-release",
        reservation.reservation_id,
        sequence_number,
        previous_sha256,
        authorization.decision_id,
        reason.value,
        finality_reference,
        source_sha256,
        order_id,
        attempt_id,
        order_event_id,
        occurred_at,
    )
    fact = object.__new__(ReservationReleaseFact)
    values: tuple[tuple[str, object], ...] = (
        ("release_event_id", release_event_id),
        ("sequence_number", sequence_number),
        ("previous_release_sha256", previous_sha256),
        ("reservation_id", reservation.reservation_id),
        ("reservation_sha256", reservation.semantic_sha256),
        ("parent_decision_id", reservation.parent_decision_id),
        ("authorization_id", authorization.decision_id),
        ("authorization_sha256", authorization.semantic_sha256),
        ("order_id", order_id),
        ("attempt_id", attempt_id),
        ("order_event_id", order_event_id),
        ("reason", reason),
        ("finality_reference", finality_reference),
        ("source_sha256", source_sha256),
        ("attempt_sha256", None if attempt is None else attempt.semantic_sha256),
        ("order_state_sha256", None if order_state is None else order_state.semantic_sha256),
        ("order_event_sha256", None if order_event is None else order_event.semantic_sha256),
        ("execution_id", execution_id),
        ("execution_revision", execution_revision),
        ("execution_head_quantity", execution_head_quantity),
        ("accounted_quantity", accounted_quantity),
        ("released_cash", _amount(released_cash, "released cash")),
        (
            "released_buy_exposure",
            _amount(released_buy_exposure, "released buy exposure"),
        ),
        (
            "released_sell_quantity",
            _amount(released_sell_quantity, "released sell quantity", whole=True),
        ),
        ("occurred_at", occurred_at),
        ("recorded_at", recorded_at),
    )
    for field_name, value in values:
        object.__setattr__(fact, field_name, value)
    fact._validate()
    project_reservation_capacity(reservation, (*prior_releases, fact))
    return fact


def record_approval_expired_unsent_release(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...],
    finality_reference: str,
    observed_at: datetime,
    recorded_at: datetime,
    prior_releases: tuple[ReservationReleaseFact, ...] = (),
) -> ReservationReleaseFact:
    """Release an expired child only from complete proven-unsent attempt evidence."""

    _authorization_for_release(reservation, authorization)
    if observed_at < authorization.expires_at:
        raise ReservationLifecycleError("approval cannot expire before its exact expiry")
    if type(parent_attempts) is not tuple or any(
        type(attempt) is not CanonicalSubmissionAttempt for attempt in parent_attempts
    ):
        raise ReservationLifecycleError("parent attempt snapshot must be an immutable tuple")
    ordering: list[tuple[str, int, str]] = []
    for attempt in parent_attempts:
        _canonical_attempt(attempt)
        if attempt.parent_decision_id != reservation.parent_decision_id:
            raise ReservationReleaseConflict("parent attempt snapshot crosses risk decisions")
        ordering.append((attempt.order_id, attempt.attempt_number, attempt.attempt_id))
        if (
            attempt.preparation.authorization_id == authorization.decision_id
            and attempt.state is not SubmissionAttemptState.ABANDONED
        ):
            raise ReservationLifecycleError(
                "approval expiry cannot release a child with an unretired prepared or sent order"
            )
        if attempt.state is SubmissionAttemptState.UNKNOWN:
            raise ReservationLifecycleError(
                "an UNKNOWN sibling freezes expiry release for the whole reservation"
            )
    if tuple(ordering) != tuple(sorted(ordering)):
        raise ReservationLifecycleError("parent attempt snapshot is not canonically ordered")
    if len(ordering) != len(set(ordering)):
        raise ReservationReleaseConflict("parent attempt snapshot duplicates an attempt")
    source_sha256 = _semantic_sha256(
        (
            RESERVATION_LIFECYCLE_CONTRACT_VERSION,
            "complete_parent_attempt_snapshot",
            reservation.parent_decision_id,
            tuple(attempt.semantic_sha256 for attempt in parent_attempts),
        )
    )
    released_cash, released_exposure, released_sell = _terminal_amounts(
        reservation,
        authorization,
        prior_releases,
    )
    if (
        prior_releases
        and _child_projection(
            project_reservation_capacity(reservation, prior_releases),
            authorization.decision_id,
        ).release_event_ids
    ):
        raise ReservationReleaseConflict("unsent approval cannot have prior economic releases")
    return _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=prior_releases,
        reason=ReservationReleaseReason.APPROVAL_EXPIRED_UNSENT,
        finality_reference=finality_reference,
        source_sha256=source_sha256,
        occurred_at=observed_at,
        recorded_at=recorded_at,
        released_cash=released_cash,
        released_buy_exposure=released_exposure,
        released_sell_quantity=released_sell,
    )


def record_broker_rejected_release(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    rejection_event: BrokerOrderEvent,
    recorded_at: datetime,
    prior_releases: tuple[ReservationReleaseFact, ...] = (),
) -> ReservationReleaseFact:
    """Release a whole child from its exact canonical broker rejection."""

    _authorization_for_release(reservation, authorization)
    _bind_attempt(reservation, authorization, attempt)
    _require_known_broker_effect(attempt)
    if (
        attempt.state is SubmissionAttemptState.RESOLVED
        and attempt.resolution is not UnknownSubmissionResolution.BROKER_REJECTED
    ):
        raise ReservationLifecycleError("resolved attempt is not a broker rejection")
    _bind_order(authorization, attempt, order_state)
    _bind_order_event(order_state, rejection_event, require_last=True)
    if (
        rejection_event.kind is not BrokerOrderEventKind.REJECTED
        or order_state.status is not CanonicalOrderStatus.REJECTED
    ):
        raise ReservationLifecycleError("broker rejection release requires rejected order state")
    released_cash, released_exposure, released_sell = _terminal_amounts(
        reservation,
        authorization,
        prior_releases,
    )
    return _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=prior_releases,
        reason=ReservationReleaseReason.BROKER_REJECTED,
        finality_reference=rejection_event.event_id,
        source_sha256=rejection_event.semantic_sha256,
        occurred_at=rejection_event.received_at,
        recorded_at=recorded_at,
        released_cash=released_cash,
        released_buy_exposure=released_exposure,
        released_sell_quantity=released_sell,
        attempt=attempt,
        order_state=order_state,
        order_event=rejection_event,
    )


def record_execution_accounted_release(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    execution_event: BrokerOrderEvent,
    accounting_reference: str,
    accounting_source_sha256: str,
    accounted_at: datetime,
    recorded_at: datetime,
    prior_releases: tuple[ReservationReleaseFact, ...] = (),
) -> ReservationReleaseFact:
    """Release only a monotone execution quantity already represented by accounting."""

    _authorization_for_release(reservation, authorization)
    _bind_attempt(reservation, authorization, attempt)
    _require_known_broker_effect(attempt)
    if (
        attempt.state is SubmissionAttemptState.RESOLVED
        and attempt.resolution is not UnknownSubmissionResolution.BROKER_ACCEPTED
    ):
        raise ReservationLifecycleError("resolved attempt has no accepted broker effect")
    _bind_order(authorization, attempt, order_state)
    _bind_order_event(order_state, execution_event, require_last=False)
    if execution_event.kind not in (
        BrokerOrderEventKind.EXECUTION,
        BrokerOrderEventKind.EXECUTION_CORRECTION,
    ):
        raise ReservationLifecycleError("execution accounting requires an execution event")
    if not any(
        execution.event_id == execution_event.event_id for execution in order_state.executions
    ):
        raise ReservationLifecycleError("superseded execution events cannot authorize new release")
    if accounted_at < execution_event.received_at:
        raise ReservationLifecycleError("execution cannot be accounted before broker receipt")
    _require_independent_source(
        accounting_source_sha256,
        (
            attempt.semantic_sha256,
            order_state.semantic_sha256,
            execution_event.semantic_sha256,
        ),
        "broker or local order evidence alone cannot prove execution accounting",
    )
    assert execution_event.execution_id is not None
    assert execution_event.execution_revision is not None
    assert execution_event.quantity is not None
    prior_accounted = exact_decimal_sum(
        fact.accounted_quantity
        for fact in prior_releases
        if fact.authorization_id == authorization.decision_id
        and fact.reason is ReservationReleaseReason.EXECUTION_ACCOUNTED
        and fact.execution_id == execution_event.execution_id
        and fact.accounted_quantity is not None
    )
    newly_accounted = exact_decimal_subtract(execution_event.quantity, prior_accounted)
    if newly_accounted <= 0:
        raise ReservationLifecycleError(
            "execution correction does not establish additional monotone capacity"
        )
    released_exposure = (
        exact_decimal_multiply(newly_accounted, authorization.maximum_execution_price)
        if authorization.side is Side.BUY
        else Decimal(0)
    )
    released_cash = released_exposure
    released_sell = newly_accounted if authorization.side is Side.SELL else Decimal(0)
    return _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=prior_releases,
        reason=ReservationReleaseReason.EXECUTION_ACCOUNTED,
        finality_reference=accounting_reference,
        source_sha256=accounting_source_sha256,
        occurred_at=accounted_at,
        recorded_at=recorded_at,
        released_cash=released_cash,
        released_buy_exposure=released_exposure,
        released_sell_quantity=released_sell,
        attempt=attempt,
        order_state=order_state,
        order_event=execution_event,
        execution_id=execution_event.execution_id,
        execution_revision=execution_event.execution_revision,
        execution_head_quantity=execution_event.quantity,
        accounted_quantity=newly_accounted,
    )


def record_reconciled_terminal_release(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState | None,
    terminal_event: BrokerOrderEvent | None,
    reconciliation_reference: str,
    reconciliation_source_sha256: str,
    reconciled_at: datetime,
    recorded_at: datetime,
    prior_releases: tuple[ReservationReleaseFact, ...] = (),
) -> ReservationReleaseFact:
    """Release residual capacity only after explicit reconciliation finality."""

    _authorization_for_release(reservation, authorization)
    _bind_attempt(reservation, authorization, attempt)
    if attempt.state in (
        SubmissionAttemptState.PENDING,
        SubmissionAttemptState.IN_FLIGHT,
        SubmissionAttemptState.UNKNOWN,
    ):
        raise ReservationLifecycleError("unresolved submission cannot be reconciled terminal")
    if (
        attempt.state is SubmissionAttemptState.RESOLVED
        and attempt.resolution is UnknownSubmissionResolution.NOT_SUBMITTED
    ):
        if order_state is not None or terminal_event is not None:
            raise ReservationLifecycleError(
                "confirmed broker absence cannot carry local order terminal evidence"
            )
        reconciliation_sha256 = attempt.events[-1].reconciliation_sha256
        assert reconciliation_sha256 is not None
        if reconciliation_source_sha256 != reconciliation_sha256:
            raise ReservationReleaseConflict(
                "not-submitted finality must use the attempt reconciliation source"
            )
        if reconciled_at < attempt.as_of:
            raise ReservationLifecycleError("reconciliation cannot predate its attempt evidence")
    else:
        if order_state is None or terminal_event is None:
            raise ReservationLifecycleError(
                "sent-order reconciliation requires exact terminal order-event evidence"
            )
        _bind_order(authorization, attempt, order_state)
        _bind_order_event(order_state, terminal_event, require_last=True)
        if order_state.status not in (
            CanonicalOrderStatus.FILLED,
            CanonicalOrderStatus.CANCELED,
            CanonicalOrderStatus.REJECTED,
        ):
            raise ReservationLifecycleError("reconciliation source is not terminal")
        if reconciled_at <= order_state.as_of:
            raise ReservationLifecycleError(
                "local terminal state alone cannot authorize release; reconciliation must be later"
            )
        _require_independent_source(
            reconciliation_source_sha256,
            (
                attempt.semantic_sha256,
                order_state.semantic_sha256,
                terminal_event.semantic_sha256,
            ),
            "local terminal state alone cannot serve as reconciliation source",
        )
    released_cash, released_exposure, released_sell = _terminal_amounts(
        reservation,
        authorization,
        prior_releases,
    )
    return _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=prior_releases,
        reason=ReservationReleaseReason.RECONCILED_TERMINAL,
        finality_reference=reconciliation_reference,
        source_sha256=reconciliation_source_sha256,
        occurred_at=reconciled_at,
        recorded_at=recorded_at,
        released_cash=released_cash,
        released_buy_exposure=released_exposure,
        released_sell_quantity=released_sell,
        attempt=attempt,
        order_state=order_state,
        order_event=terminal_event,
    )


def record_simulation_horizon_final_release(
    *,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    order_state: CanonicalOrderState,
    last_order_event: BrokerOrderEvent | None,
    horizon_reference: str,
    horizon_source_sha256: str,
    horizon_at: datetime,
    recorded_at: datetime,
    prior_releases: tuple[ReservationReleaseFact, ...] = (),
) -> ReservationReleaseFact:
    """Release residual simulated capacity from one explicitly sealed final horizon."""

    _authorization_for_release(reservation, authorization)
    _bind_attempt(reservation, authorization, attempt)
    _require_known_broker_effect(attempt)
    if (
        attempt.state is SubmissionAttemptState.RESOLVED
        and attempt.resolution is not UnknownSubmissionResolution.BROKER_ACCEPTED
    ):
        raise ReservationLifecycleError("simulation order has no accepted broker effect")
    _bind_order(authorization, attempt, order_state)
    if order_state.broker_events:
        if last_order_event is None:
            raise ReservationLifecycleError("sealed horizon omitted the latest broker event")
        _bind_order_event(order_state, last_order_event, require_last=True)
    elif last_order_event is not None:
        raise ReservationReleaseConflict("sealed horizon invented an order event")
    if horizon_at < max(attempt.as_of, order_state.as_of):
        raise ReservationLifecycleError("simulation horizon predates its complete order evidence")
    local_sha256s = (
        attempt.semantic_sha256,
        order_state.semantic_sha256,
        *(() if last_order_event is None else (last_order_event.semantic_sha256,)),
    )
    _require_independent_source(
        horizon_source_sha256,
        local_sha256s,
        "local order state alone cannot prove a sealed simulation horizon",
    )
    released_cash, released_exposure, released_sell = _terminal_amounts(
        reservation,
        authorization,
        prior_releases,
    )
    return _new_release_fact(
        reservation=reservation,
        authorization=authorization,
        prior_releases=prior_releases,
        reason=ReservationReleaseReason.SIMULATION_HORIZON_FINAL,
        finality_reference=horizon_reference,
        source_sha256=horizon_source_sha256,
        occurred_at=horizon_at,
        recorded_at=recorded_at,
        released_cash=released_cash,
        released_buy_exposure=released_exposure,
        released_sell_quantity=released_sell,
        attempt=attempt,
        order_state=order_state,
        order_event=last_order_event,
    )
