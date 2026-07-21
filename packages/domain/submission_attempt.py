"""Pure durable-preparation and lifecycle contracts for broker submissions.

The reducer in this module prepares deterministic evidence that must be made
durable before a broker call.  It performs no persistence or network I/O and
cannot establish that a caller supplied a complete database snapshot.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from packages.domain.account_coordinator import AccountFenceReceipt
from packages.domain.batch_risk import (
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
)
from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import OrderIntent, require_utc
from packages.domain.risk import intent_payload_hash

SUBMISSION_ATTEMPT_CONTRACT_VERSION = "phase2-submission-attempt-v2"
MAX_REQUEST_FIELDS = 128
MAX_REQUEST_KEY_LENGTH = 128
MAX_REQUEST_STRING_LENGTH = 4096
MAX_REQUEST_PAYLOAD_BYTES = 262_144
MAX_REQUEST_INTEGER_BITS = 256

type RequestValue = None | bool | int | str | Decimal


class SubmissionAttemptError(ValueError):
    """Submission evidence is malformed or violates its lifecycle."""


class SubmissionAttemptConflict(SubmissionAttemptError):
    """An immutable submission identity has conflicting semantics."""


class UnknownSubmissionBarrier(SubmissionAttemptError):
    """At least one parent-batch submission has an unresolved outcome."""


class BlindResubmissionError(SubmissionAttemptError):
    """A new attempt would duplicate an order without confirmed absence."""


class SubmissionAttemptState(StrEnum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    ABANDONED = "abandoned"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"
    RESOLVED = "resolved"


class UnknownSubmissionResolution(StrEnum):
    NOT_SUBMITTED = "not_submitted"
    BROKER_ACCEPTED = "broker_accepted"
    BROKER_REJECTED = "broker_rejected"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise SubmissionAttemptError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise SubmissionAttemptError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SubmissionAttemptError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise SubmissionAttemptError(str(error)) from error


def _request_value(value: object) -> RequestValue:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > MAX_REQUEST_INTEGER_BITS:
            raise SubmissionAttemptError("broker request integer exceeds its size limit")
        return value
    if type(value) is str:
        if len(value) > MAX_REQUEST_STRING_LENGTH or any(
            ord(character) < 32 for character in value
        ):
            raise SubmissionAttemptError("broker request string contains unsupported text")
        return value
    if type(value) is Decimal:
        if not value.is_finite():
            raise SubmissionAttemptError("broker request Decimal must be finite")
        return canonical_decimal(value)
    raise SubmissionAttemptError(
        "broker request values must be null, bool, int, str, or exact Decimal"
    )


def _order_id(intent: OrderIntent) -> str:
    return canonical_id("order", intent.intent_id, intent_payload_hash(intent))


def _client_order_id(order_id: str) -> str:
    return f"aqt-{order_id.replace('-', '')[:24]}"


@dataclass(frozen=True, slots=True, init=False)
class BrokerSubmissionRequest:
    """Bounded canonical adapter request; no transport authority is implied."""

    adapter_id: str
    adapter_version: str
    operation: str
    order_id: str
    client_order_id: str
    intent_payload_sha256: str
    _payload: tuple[tuple[str, RequestValue], ...]
    request_sha256: str

    def __init__(
        self,
        *,
        adapter_id: str,
        adapter_version: str,
        operation: str,
        order_id: str,
        client_order_id: str,
        intent_payload_sha256: str,
        payload: Mapping[str, object],
    ) -> None:
        for text_value, field_name in (
            (adapter_id, "broker adapter ID"),
            (adapter_version, "broker adapter version"),
            (operation, "broker operation"),
            (order_id, "broker request order ID"),
            (client_order_id, "broker request client order ID"),
        ):
            _require_text(text_value, field_name)
        _require_sha256(intent_payload_sha256, "broker request intent digest")
        if not isinstance(payload, Mapping):
            raise SubmissionAttemptError("broker request payload must be a mapping")
        if not payload or len(payload) > MAX_REQUEST_FIELDS:
            raise SubmissionAttemptError("broker request payload field count is invalid")
        normalized: list[tuple[str, RequestValue]] = []
        for key, payload_value in payload.items():
            _require_text(key, "broker request key", maximum=MAX_REQUEST_KEY_LENGTH)
            normalized.append((key, _request_value(payload_value)))
        canonical_payload = tuple(sorted(normalized))
        if len({key for key, _ in canonical_payload}) != len(canonical_payload):
            raise SubmissionAttemptError("broker request keys must be unique")
        if len(canonical_json_bytes(canonical_payload)) > MAX_REQUEST_PAYLOAD_BYTES:
            raise SubmissionAttemptError("broker request payload exceeds its encoded size limit")
        material = (
            SUBMISSION_ATTEMPT_CONTRACT_VERSION,
            "broker_request",
            adapter_id,
            adapter_version,
            operation,
            order_id,
            client_order_id,
            intent_payload_sha256,
            canonical_payload,
        )
        for field_name, attribute_value in (
            ("adapter_id", adapter_id),
            ("adapter_version", adapter_version),
            ("operation", operation),
            ("order_id", order_id),
            ("client_order_id", client_order_id),
            ("intent_payload_sha256", intent_payload_sha256),
            ("_payload", canonical_payload),
            ("request_sha256", _semantic_sha256(material)),
        ):
            object.__setattr__(self, field_name, attribute_value)

    @property
    def payload(self) -> Mapping[str, RequestValue]:
        return MappingProxyType(dict(self._payload))

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            SUBMISSION_ATTEMPT_CONTRACT_VERSION,
            "broker_request",
            self.adapter_id,
            self.adapter_version,
            self.operation,
            self.order_id,
            self.client_order_id,
            self.intent_payload_sha256,
            self._payload,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.request_sha256


def create_broker_submission_request(
    *,
    intent: OrderIntent,
    adapter_id: str,
    adapter_version: str,
    operation: str,
    payload: Mapping[str, object],
) -> BrokerSubmissionRequest:
    """Bind an adapter payload to the deterministic logical-order identity."""

    if type(intent) is not OrderIntent:
        raise SubmissionAttemptError("broker request requires an exact OrderIntent")
    intent.__post_init__()
    order_id = _order_id(intent)
    return BrokerSubmissionRequest(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        operation=operation,
        order_id=order_id,
        client_order_id=_client_order_id(order_id),
        intent_payload_sha256=intent_payload_hash(intent),
        payload=payload,
    )


@dataclass(frozen=True, slots=True, init=False)
class SubmissionAttemptPreparation:
    """Proof-constructed row that must be durable before dispatch begins."""

    attempt_id: str
    attempt_number: int
    order_id: str
    client_order_id: str
    parent_decision_id: str
    authorization_id: str
    reservation_id: str
    account_id: str
    intent: OrderIntent
    intent_payload_sha256: str
    risk_decision: BatchRiskDecision
    risk_decision_sha256: str
    authorization_sha256: str
    fence_receipt: AccountFenceReceipt
    fence_receipt_sha256: str
    request: BrokerSubmissionRequest
    prepared_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SubmissionAttemptPreparation must be proof-constructed")

    def _validate(self) -> None:
        for value, field_name in (
            (self.attempt_id, "submission attempt ID"),
            (self.order_id, "submission order ID"),
            (self.client_order_id, "submission client order ID"),
            (self.parent_decision_id, "submission parent decision ID"),
            (self.authorization_id, "submission authorization ID"),
            (self.reservation_id, "submission reservation ID"),
            (self.account_id, "submission account ID"),
        ):
            _require_text(value, field_name)
        if type(self.attempt_number) is not int or self.attempt_number <= 0:
            raise SubmissionAttemptError("submission attempt number must be positive")
        if type(self.intent) is not OrderIntent:
            raise SubmissionAttemptError("submission preparation requires an exact OrderIntent")
        self.intent.__post_init__()
        if type(self.risk_decision) is not BatchRiskDecision:
            raise SubmissionAttemptError("submission preparation requires an exact risk decision")
        self.risk_decision.__post_init__()
        if type(self.fence_receipt) is not AccountFenceReceipt:
            raise SubmissionAttemptError("submission preparation requires an exact fence receipt")
        self.fence_receipt._validate()
        if type(self.request) is not BrokerSubmissionRequest:
            raise SubmissionAttemptError("submission preparation requires an exact broker request")
        for value, field_name in (
            (self.intent_payload_sha256, "submission intent digest"),
            (self.risk_decision_sha256, "submission risk decision digest"),
            (self.authorization_sha256, "submission authorization digest"),
            (self.fence_receipt_sha256, "submission fence receipt digest"),
        ):
            _require_sha256(value, field_name)
        _require_utc(self.prepared_at, "submission prepared_at")
        authorization = _authorization_for_intent(self.risk_decision, self.intent)
        expected_order_id = _order_id(self.intent)
        expected_client_order_id = _client_order_id(expected_order_id)
        expected_attempt_id = canonical_id(
            "submission-attempt",
            expected_order_id,
            self.attempt_number,
            self.risk_decision.semantic_sha256,
            self.fence_receipt.semantic_sha256,
            self.request.semantic_sha256,
        )
        for actual, expected, field_name in (
            (self.attempt_id, expected_attempt_id, "attempt identity"),
            (self.order_id, expected_order_id, "order identity"),
            (self.client_order_id, expected_client_order_id, "client order identity"),
            (
                self.parent_decision_id,
                self.risk_decision.decision_id,
                "parent risk decision",
            ),
            (self.authorization_id, authorization.decision_id, "authorization identity"),
            (self.reservation_id, authorization.reservation_id, "reservation identity"),
            (self.account_id, self.risk_decision.account_id, "account identity"),
            (
                self.intent_payload_sha256,
                intent_payload_hash(self.intent),
                "intent payload digest",
            ),
            (
                self.risk_decision_sha256,
                self.risk_decision.semantic_sha256,
                "risk decision digest",
            ),
            (
                self.authorization_sha256,
                authorization.semantic_sha256,
                "authorization digest",
            ),
            (
                self.fence_receipt_sha256,
                self.fence_receipt.semantic_sha256,
                "fence receipt digest",
            ),
        ):
            if actual != expected:
                raise SubmissionAttemptConflict(
                    f"submission {field_name} does not match its exact source evidence"
                )
        if self.fence_receipt.fence.account_id != self.account_id:
            raise SubmissionAttemptConflict("fence receipt belongs to a different account")
        if self.request.order_id != self.order_id:
            raise SubmissionAttemptConflict("broker request belongs to a different order")
        if self.request.client_order_id != self.client_order_id:
            raise SubmissionAttemptConflict("broker request changed the stable client order ID")
        if self.request.intent_payload_sha256 != self.intent_payload_sha256:
            raise SubmissionAttemptConflict("broker request changed the intent payload digest")
        if self.fence_receipt.validated_at < self.risk_decision.evaluated_at:
            raise SubmissionAttemptError("fence receipt must be current after risk evaluation")
        if self.prepared_at < self.fence_receipt.validated_at:
            raise SubmissionAttemptError("submission cannot be prepared before fence validation")
        if self.prepared_at >= self.fence_receipt.valid_until:
            raise SubmissionAttemptError("submission preparation requires a current fence receipt")
        if self.prepared_at >= self.risk_decision.expires_at:
            raise SubmissionAttemptError("submission preparation requires current risk approval")
        if self.prepared_at >= self.intent.expires_at:
            raise SubmissionAttemptError("submission preparation requires a current intent")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            SUBMISSION_ATTEMPT_CONTRACT_VERSION,
            "preparation",
            self.attempt_id,
            self.attempt_number,
            self.order_id,
            self.client_order_id,
            self.parent_decision_id,
            self.authorization_id,
            self.reservation_id,
            self.account_id,
            self.intent.semantic_sha256,
            self.intent_payload_sha256,
            self.risk_decision_sha256,
            self.authorization_sha256,
            self.fence_receipt_sha256,
            self.request.semantic_sha256,
            self.prepared_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class SubmissionAttemptEvent:
    """One append-only state fact for a prepared submission attempt."""

    event_id: str
    attempt_id: str
    sequence_number: int
    state: SubmissionAttemptState
    occurred_at: datetime
    recorded_at: datetime
    previous_event_sha256: str | None
    dispatch_fence_receipt: AccountFenceReceipt | None
    response_sha256: str | None
    broker_order_id: str | None
    error_class: str | None
    resolution: UnknownSubmissionResolution | None
    reconciliation_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SubmissionAttemptEvent must be created by lifecycle reducers")

    def _validate(self) -> None:
        _require_text(self.event_id, "submission event ID")
        _require_text(self.attempt_id, "submission event attempt ID")
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise SubmissionAttemptError("submission event sequence must be positive")
        if type(self.state) is not SubmissionAttemptState:
            raise SubmissionAttemptError("submission event state must be exact")
        _require_utc(self.occurred_at, "submission event occurred_at")
        _require_utc(self.recorded_at, "submission event recorded_at")
        if self.recorded_at < self.occurred_at:
            raise SubmissionAttemptError("submission event cannot be recorded before it occurred")
        _require_optional_sha256(self.previous_event_sha256, "previous submission event digest")
        if self.dispatch_fence_receipt is not None:
            if type(self.dispatch_fence_receipt) is not AccountFenceReceipt:
                raise SubmissionAttemptError("dispatch receipt must be an exact fence receipt")
            self.dispatch_fence_receipt._validate()
        _require_optional_sha256(self.response_sha256, "broker response digest")
        _require_optional_sha256(self.reconciliation_sha256, "reconciliation digest")
        if self.broker_order_id is not None:
            _require_text(self.broker_order_id, "broker order ID")
        if self.error_class is not None:
            _require_text(self.error_class, "submission error class")
        if self.resolution is not None and type(self.resolution) is not UnknownSubmissionResolution:
            raise SubmissionAttemptError("unknown submission resolution must be exact")
        if self.sequence_number == 1:
            if self.state is not SubmissionAttemptState.PENDING:
                raise SubmissionAttemptError("first submission event must be pending")
            if self.previous_event_sha256 is not None:
                raise SubmissionAttemptError("first submission event cannot have a predecessor")
        elif self.previous_event_sha256 is None:
            raise SubmissionAttemptError("successor submission event requires its predecessor")
        self._validate_shape()
        expected_event_id = canonical_id(
            "submission-attempt-event",
            self.attempt_id,
            self.sequence_number,
            self.state.value,
            self.occurred_at,
            self.recorded_at,
            self.previous_event_sha256,
            (
                None
                if self.dispatch_fence_receipt is None
                else self.dispatch_fence_receipt.semantic_sha256
            ),
            self.response_sha256,
            self.broker_order_id,
            self.error_class,
            None if self.resolution is None else self.resolution.value,
            self.reconciliation_sha256,
        )
        if self.event_id != expected_event_id:
            raise SubmissionAttemptConflict("submission event ID is not canonically derived")

    def _validate_shape(self) -> None:
        if self.state is SubmissionAttemptState.PENDING:
            if any(
                value is not None
                for value in (
                    self.dispatch_fence_receipt,
                    self.response_sha256,
                    self.broker_order_id,
                    self.error_class,
                    self.resolution,
                    self.reconciliation_sha256,
                )
            ):
                raise SubmissionAttemptError("pending event has dispatch or outcome evidence")
            return
        if self.state is SubmissionAttemptState.IN_FLIGHT:
            if self.dispatch_fence_receipt is None:
                raise SubmissionAttemptError("in-flight event requires dispatch fence evidence")
            if any(
                value is not None
                for value in (
                    self.response_sha256,
                    self.broker_order_id,
                    self.error_class,
                    self.resolution,
                    self.reconciliation_sha256,
                )
            ):
                raise SubmissionAttemptError("in-flight event has outcome evidence")
            return
        if self.state is SubmissionAttemptState.ABANDONED:
            if self.error_class is None:
                raise SubmissionAttemptError("abandoned submission requires a recovery reason")
            if any(
                value is not None
                for value in (
                    self.dispatch_fence_receipt,
                    self.response_sha256,
                    self.broker_order_id,
                    self.resolution,
                    self.reconciliation_sha256,
                )
            ):
                raise SubmissionAttemptError(
                    "abandoned submission has invented dispatch or broker evidence"
                )
            return
        if self.state is SubmissionAttemptState.CONFIRMED:
            if self.response_sha256 is None or self.broker_order_id is None:
                raise SubmissionAttemptError(
                    "confirmed submission requires response and broker order evidence"
                )
            if any(
                value is not None
                for value in (
                    self.dispatch_fence_receipt,
                    self.error_class,
                    self.resolution,
                    self.reconciliation_sha256,
                )
            ):
                raise SubmissionAttemptError("confirmed submission has incompatible evidence")
            return
        if self.state is SubmissionAttemptState.UNKNOWN:
            if self.error_class is None:
                raise SubmissionAttemptError("unknown submission requires an error class")
            if any(
                value is not None
                for value in (
                    self.dispatch_fence_receipt,
                    self.response_sha256,
                    self.broker_order_id,
                    self.resolution,
                    self.reconciliation_sha256,
                )
            ):
                raise SubmissionAttemptError("unknown submission has invented outcome evidence")
            return
        if self.resolution is None or self.reconciliation_sha256 is None:
            raise SubmissionAttemptError(
                "resolved unknown submission requires resolution and reconciliation evidence"
            )
        if self.error_class is not None:
            raise SubmissionAttemptError("resolved submission cannot replace its prior error class")
        if self.dispatch_fence_receipt is not None:
            raise SubmissionAttemptError("resolved submission cannot carry dispatch fence evidence")
        if self.resolution is UnknownSubmissionResolution.NOT_SUBMITTED:
            if self.response_sha256 is not None or self.broker_order_id is not None:
                raise SubmissionAttemptError(
                    "confirmed absence cannot retain broker outcome evidence"
                )
        elif self.resolution is UnknownSubmissionResolution.BROKER_ACCEPTED:
            if self.response_sha256 is None or self.broker_order_id is None:
                raise SubmissionAttemptError(
                    "accepted unknown submission requires response and broker order evidence"
                )
        elif self.response_sha256 is None:
            raise SubmissionAttemptError("rejected unknown submission requires response evidence")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            SUBMISSION_ATTEMPT_CONTRACT_VERSION,
            "event",
            self.event_id,
            self.attempt_id,
            self.sequence_number,
            self.state.value,
            self.occurred_at,
            self.recorded_at,
            self.previous_event_sha256,
            (
                None
                if self.dispatch_fence_receipt is None
                else self.dispatch_fence_receipt.semantic_sha256
            ),
            self.response_sha256,
            self.broker_order_id,
            self.error_class,
            None if self.resolution is None else self.resolution.value,
            self.reconciliation_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class CanonicalSubmissionAttempt:
    """Reducer-produced projection over one preparation and append-only events."""

    preparation: SubmissionAttemptPreparation
    events: tuple[SubmissionAttemptEvent, ...]
    state: SubmissionAttemptState
    resolution: UnknownSubmissionResolution | None
    response_sha256: str | None
    broker_order_id: str | None
    unknown_error_class: str | None
    as_of: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CanonicalSubmissionAttempt must be produced by its reducer")

    @property
    def attempt_id(self) -> str:
        return self.preparation.attempt_id

    @property
    def attempt_number(self) -> int:
        return self.preparation.attempt_number

    @property
    def order_id(self) -> str:
        return self.preparation.order_id

    @property
    def parent_decision_id(self) -> str:
        return self.preparation.parent_decision_id

    @property
    def may_resubmit(self) -> bool:
        return self.state is SubmissionAttemptState.ABANDONED or (
            self.state is SubmissionAttemptState.RESOLVED
            and self.resolution is UnknownSubmissionResolution.NOT_SUBMITTED
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                SUBMISSION_ATTEMPT_CONTRACT_VERSION,
                "projection",
                self.preparation.semantic_sha256,
                tuple(event.semantic_sha256 for event in self.events),
                self.state.value,
                None if self.resolution is None else self.resolution.value,
                self.response_sha256,
                self.broker_order_id,
                self.unknown_error_class,
                self.as_of,
            )
        )


def _authorization_for_intent(
    decision: BatchRiskDecision,
    intent: OrderIntent,
) -> BatchRiskAuthorization:
    if decision.status is not BatchRiskDecisionStatus.APPROVED:
        raise SubmissionAttemptError("submission requires an approved batch risk decision")
    matches = tuple(
        authorization
        for authorization in decision.authorizations
        if authorization.intent_id == intent.intent_id
    )
    if len(matches) != 1:
        raise SubmissionAttemptConflict(
            "risk decision must contain exactly one authorization for the intent"
        )
    authorization = matches[0]
    expected = (
        (authorization.intent_batch_id, intent.intent_batch_id, "intent batch"),
        (authorization.intent_payload_hash, intent_payload_hash(intent), "intent payload"),
        (authorization.instrument_id, intent.instrument_id, "instrument"),
        (authorization.symbol, intent.symbol, "symbol"),
        (authorization.side, intent.side, "side"),
        (authorization.quantity, intent.quantity, "quantity"),
        (authorization.reference_price, intent.reference_price, "reference price"),
    )
    if any(actual != intended for actual, intended, _ in expected):
        mismatch = next(
            field_name for actual, intended, field_name in expected if actual != intended
        )
        raise SubmissionAttemptConflict(
            f"risk authorization {mismatch} does not match the exact intent"
        )
    return authorization


def _create_preparation(
    *,
    intent: OrderIntent,
    risk_decision: BatchRiskDecision,
    fence_receipt: AccountFenceReceipt,
    request: BrokerSubmissionRequest,
    attempt_number: int,
    prepared_at: datetime,
) -> SubmissionAttemptPreparation:
    authorization = _authorization_for_intent(risk_decision, intent)
    order_id = _order_id(intent)
    attempt_id = canonical_id(
        "submission-attempt",
        order_id,
        attempt_number,
        risk_decision.semantic_sha256,
        fence_receipt.semantic_sha256,
        request.semantic_sha256,
    )
    preparation = object.__new__(SubmissionAttemptPreparation)
    for field_name, value in (
        ("attempt_id", attempt_id),
        ("attempt_number", attempt_number),
        ("order_id", order_id),
        ("client_order_id", _client_order_id(order_id)),
        ("parent_decision_id", risk_decision.decision_id),
        ("authorization_id", authorization.decision_id),
        ("reservation_id", authorization.reservation_id),
        ("account_id", risk_decision.account_id),
        ("intent", intent),
        ("intent_payload_sha256", intent_payload_hash(intent)),
        ("risk_decision", risk_decision),
        ("risk_decision_sha256", risk_decision.semantic_sha256),
        ("authorization_sha256", authorization.semantic_sha256),
        ("fence_receipt", fence_receipt),
        ("fence_receipt_sha256", fence_receipt.semantic_sha256),
        ("request", request),
        ("prepared_at", prepared_at),
    ):
        object.__setattr__(preparation, field_name, value)
    preparation._validate()
    return preparation


def _create_event(
    *,
    attempt_id: str,
    sequence_number: int,
    state: SubmissionAttemptState,
    occurred_at: datetime,
    recorded_at: datetime,
    previous_event_sha256: str | None,
    dispatch_fence_receipt: AccountFenceReceipt | None = None,
    response_sha256: str | None = None,
    broker_order_id: str | None = None,
    error_class: str | None = None,
    resolution: UnknownSubmissionResolution | None = None,
    reconciliation_sha256: str | None = None,
) -> SubmissionAttemptEvent:
    event_id = canonical_id(
        "submission-attempt-event",
        attempt_id,
        sequence_number,
        state.value,
        occurred_at,
        recorded_at,
        previous_event_sha256,
        (None if dispatch_fence_receipt is None else dispatch_fence_receipt.semantic_sha256),
        response_sha256,
        broker_order_id,
        error_class,
        None if resolution is None else resolution.value,
        reconciliation_sha256,
    )
    event = object.__new__(SubmissionAttemptEvent)
    for field_name, value in (
        ("event_id", event_id),
        ("attempt_id", attempt_id),
        ("sequence_number", sequence_number),
        ("state", state),
        ("occurred_at", occurred_at),
        ("recorded_at", recorded_at),
        ("previous_event_sha256", previous_event_sha256),
        ("dispatch_fence_receipt", dispatch_fence_receipt),
        ("response_sha256", response_sha256),
        ("broker_order_id", broker_order_id),
        ("error_class", error_class),
        ("resolution", resolution),
        ("reconciliation_sha256", reconciliation_sha256),
    ):
        object.__setattr__(event, field_name, value)
    event._validate()
    return event


def reduce_submission_attempt(
    preparation: SubmissionAttemptPreparation,
    events: tuple[SubmissionAttemptEvent, ...],
) -> CanonicalSubmissionAttempt:
    """Rebuild one canonical attempt projection from exact append-only facts."""

    if type(preparation) is not SubmissionAttemptPreparation:
        raise SubmissionAttemptError("submission reducer requires an exact preparation")
    preparation._validate()
    if (
        type(events) is not tuple
        or not events
        or any(type(event) is not SubmissionAttemptEvent for event in events)
    ):
        raise SubmissionAttemptError("submission reducer requires immutable exact events")
    expected_states = {
        SubmissionAttemptState.PENDING: (
            SubmissionAttemptState.IN_FLIGHT,
            SubmissionAttemptState.ABANDONED,
        ),
        SubmissionAttemptState.IN_FLIGHT: (
            SubmissionAttemptState.CONFIRMED,
            SubmissionAttemptState.UNKNOWN,
        ),
        SubmissionAttemptState.ABANDONED: (),
        SubmissionAttemptState.UNKNOWN: (SubmissionAttemptState.RESOLVED,),
        SubmissionAttemptState.CONFIRMED: (),
        SubmissionAttemptState.RESOLVED: (),
    }
    prior: SubmissionAttemptEvent | None = None
    unknown_error_class: str | None = None
    event_ids: set[str] = set()
    for sequence_number, event in enumerate(events, start=1):
        event._validate()
        if event.event_id in event_ids:
            raise SubmissionAttemptConflict("submission event identity is reused")
        event_ids.add(event.event_id)
        if event.attempt_id != preparation.attempt_id:
            raise SubmissionAttemptConflict("submission event belongs to another attempt")
        if event.sequence_number != sequence_number:
            raise SubmissionAttemptError("submission event sequence must be contiguous")
        if prior is None:
            if event.state is not SubmissionAttemptState.PENDING:
                raise SubmissionAttemptError("submission lifecycle must begin pending")
            if event.occurred_at != preparation.prepared_at:
                raise SubmissionAttemptError("pending event must share preparation time")
        else:
            if event.state not in expected_states[prior.state]:
                raise SubmissionAttemptError(
                    f"invalid submission transition {prior.state.value} -> {event.state.value}"
                )
            if event.previous_event_sha256 != prior.semantic_sha256:
                raise SubmissionAttemptConflict(
                    "submission event does not chain to its exact predecessor"
                )
            if event.occurred_at < prior.occurred_at or event.recorded_at < prior.recorded_at:
                raise SubmissionAttemptError("submission event history cannot move backwards")
        if event.state is SubmissionAttemptState.IN_FLIGHT:
            dispatch_receipt = event.dispatch_fence_receipt
            assert dispatch_receipt is not None
            if dispatch_receipt.fence != preparation.fence_receipt.fence:
                raise SubmissionAttemptConflict(
                    "dispatch receipt changed the prepared stable fence"
                )
            if dispatch_receipt.policy_sha256 != preparation.fence_receipt.policy_sha256:
                raise SubmissionAttemptConflict("dispatch receipt changed the fence policy")
            if dispatch_receipt.validated_at != event.occurred_at:
                raise SubmissionAttemptError(
                    "dispatch receipt must be validated at dispatch occurrence"
                )
            if event.occurred_at >= dispatch_receipt.valid_until:
                raise SubmissionAttemptError("dispatch requires a current fence receipt")
            if event.occurred_at >= preparation.risk_decision.expires_at:
                raise SubmissionAttemptError("dispatch cannot begin after risk approval expiry")
            if event.occurred_at >= preparation.intent.expires_at:
                raise SubmissionAttemptError("dispatch cannot begin after intent expiry")
        if event.state is SubmissionAttemptState.UNKNOWN:
            unknown_error_class = event.error_class
        prior = event
    assert prior is not None
    projection = object.__new__(CanonicalSubmissionAttempt)
    for field_name, value in (
        ("preparation", preparation),
        ("events", events),
        ("state", prior.state),
        ("resolution", prior.resolution),
        ("response_sha256", prior.response_sha256),
        ("broker_order_id", prior.broker_order_id),
        ("unknown_error_class", unknown_error_class),
        ("as_of", prior.recorded_at),
    ):
        object.__setattr__(projection, field_name, value)
    return projection


def _require_canonical_attempt(attempt: CanonicalSubmissionAttempt) -> None:
    if type(attempt) is not CanonicalSubmissionAttempt:
        raise SubmissionAttemptError("operation requires an exact canonical submission attempt")
    if reduce_submission_attempt(attempt.preparation, attempt.events) != attempt:
        raise SubmissionAttemptConflict("submission attempt is not reducer-produced")


@dataclass(frozen=True, slots=True, init=False)
class ParentBatchSubmissionBarrier:
    """Projection of unresolved UNKNOWN outcomes across one parent decision."""

    parent_decision_id: str
    attempt_sha256s: tuple[str, ...]
    unknown_attempt_ids: tuple[str, ...]
    barrier_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ParentBatchSubmissionBarrier must be reducer-produced")

    @property
    def blocked(self) -> bool:
        return bool(self.unknown_attempt_ids)

    @property
    def semantic_sha256(self) -> str:
        return self.barrier_sha256


def submission_barrier_for_parent(
    *,
    parent_decision_id: str,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> ParentBatchSubmissionBarrier:
    """Project UNKNOWN outcomes from a caller-supplied complete parent snapshot."""

    _require_text(parent_decision_id, "barrier parent decision ID")
    if type(attempts) is not tuple or any(
        type(attempt) is not CanonicalSubmissionAttempt for attempt in attempts
    ):
        raise SubmissionAttemptError("barrier attempts must be immutable exact values")
    for attempt in attempts:
        _require_canonical_attempt(attempt)
        if attempt.parent_decision_id != parent_decision_id:
            raise SubmissionAttemptConflict("barrier attempt belongs to another parent decision")
    ordering = tuple(
        (attempt.order_id, attempt.attempt_number, attempt.attempt_id) for attempt in attempts
    )
    if ordering != tuple(sorted(ordering)):
        raise SubmissionAttemptError("barrier attempts must use canonical order and attempt order")
    attempt_ids = tuple(attempt.attempt_id for attempt in attempts)
    if len(attempt_ids) != len(set(attempt_ids)):
        raise SubmissionAttemptConflict("barrier attempt identities must be unique")
    attempt_sha256s = tuple(attempt.semantic_sha256 for attempt in attempts)
    unknown_attempt_ids = tuple(
        attempt.attempt_id
        for attempt in attempts
        if attempt.state is SubmissionAttemptState.UNKNOWN
    )
    material = (
        SUBMISSION_ATTEMPT_CONTRACT_VERSION,
        "parent_batch_barrier",
        parent_decision_id,
        attempt_sha256s,
        unknown_attempt_ids,
    )
    barrier = object.__new__(ParentBatchSubmissionBarrier)
    for field_name, value in (
        ("parent_decision_id", parent_decision_id),
        ("attempt_sha256s", attempt_sha256s),
        ("unknown_attempt_ids", unknown_attempt_ids),
        ("barrier_sha256", _semantic_sha256(material)),
    ):
        object.__setattr__(barrier, field_name, value)
    return barrier


def require_parent_batch_submission_clear(
    *,
    parent_decision_id: str,
    attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> ParentBatchSubmissionBarrier:
    barrier = submission_barrier_for_parent(
        parent_decision_id=parent_decision_id,
        attempts=attempts,
    )
    if barrier.blocked:
        raise UnknownSubmissionBarrier(
            "parent batch has an unresolved UNKNOWN submission; dispatch is fenced"
        )
    return barrier


def prepare_submission_attempt(
    *,
    intent: OrderIntent,
    risk_decision: BatchRiskDecision,
    fence_receipt: AccountFenceReceipt,
    request: BrokerSubmissionRequest,
    prepared_at: datetime,
    recorded_at: datetime,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> CanonicalSubmissionAttempt:
    """Prepare a pending attempt after proving approval, fence, and retry safety."""

    if type(intent) is not OrderIntent:
        raise SubmissionAttemptError("submission preparation requires an exact OrderIntent")
    if type(risk_decision) is not BatchRiskDecision:
        raise SubmissionAttemptError("submission preparation requires an exact risk decision")
    if type(fence_receipt) is not AccountFenceReceipt:
        raise SubmissionAttemptError("submission preparation requires an exact fence receipt")
    if type(request) is not BrokerSubmissionRequest:
        raise SubmissionAttemptError("submission preparation requires an exact broker request")
    _require_utc(prepared_at, "submission prepared_at")
    _require_utc(recorded_at, "pending event recorded_at")
    if recorded_at < prepared_at:
        raise SubmissionAttemptError("pending event cannot be recorded before preparation")
    require_parent_batch_submission_clear(
        parent_decision_id=risk_decision.decision_id,
        attempts=parent_attempts,
    )
    order_id = _order_id(intent)
    prior_order_attempts = tuple(
        attempt for attempt in parent_attempts if attempt.order_id == order_id
    )
    if prior_order_attempts:
        expected_numbers = tuple(range(1, len(prior_order_attempts) + 1))
        if tuple(attempt.attempt_number for attempt in prior_order_attempts) != expected_numbers:
            raise SubmissionAttemptConflict("prior order attempts are not contiguous")
        if not prior_order_attempts[-1].may_resubmit:
            raise BlindResubmissionError(
                "a new attempt requires durable proof that the prior request was never dispatched "
                "or was not submitted"
            )
    attempt_number = len(prior_order_attempts) + 1
    preparation = _create_preparation(
        intent=intent,
        risk_decision=risk_decision,
        fence_receipt=fence_receipt,
        request=request,
        attempt_number=attempt_number,
        prepared_at=prepared_at,
    )
    pending = _create_event(
        attempt_id=preparation.attempt_id,
        sequence_number=1,
        state=SubmissionAttemptState.PENDING,
        occurred_at=prepared_at,
        recorded_at=recorded_at,
        previous_event_sha256=None,
    )
    return reduce_submission_attempt(preparation, (pending,))


def _append_event(
    attempt: CanonicalSubmissionAttempt,
    *,
    state: SubmissionAttemptState,
    occurred_at: datetime,
    recorded_at: datetime,
    response_sha256: str | None = None,
    broker_order_id: str | None = None,
    error_class: str | None = None,
    resolution: UnknownSubmissionResolution | None = None,
    reconciliation_sha256: str | None = None,
    dispatch_fence_receipt: AccountFenceReceipt | None = None,
) -> CanonicalSubmissionAttempt:
    _require_canonical_attempt(attempt)
    previous = attempt.events[-1]
    event = _create_event(
        attempt_id=attempt.attempt_id,
        sequence_number=len(attempt.events) + 1,
        state=state,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        previous_event_sha256=previous.semantic_sha256,
        dispatch_fence_receipt=dispatch_fence_receipt,
        response_sha256=response_sha256,
        broker_order_id=broker_order_id,
        error_class=error_class,
        resolution=resolution,
        reconciliation_sha256=reconciliation_sha256,
    )
    return reduce_submission_attempt(attempt.preparation, (*attempt.events, event))


def mark_submission_in_flight(
    attempt: CanonicalSubmissionAttempt,
    *,
    dispatch_fence_receipt: AccountFenceReceipt,
    occurred_at: datetime,
    recorded_at: datetime,
) -> CanonicalSubmissionAttempt:
    """Durably mark dispatch immediately before invoking the broker adapter."""

    return _append_event(
        attempt,
        state=SubmissionAttemptState.IN_FLIGHT,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        dispatch_fence_receipt=dispatch_fence_receipt,
    )


def _abandon_pending_submission(
    attempt: CanonicalSubmissionAttempt,
    *,
    occurred_at: datetime,
    recorded_at: datetime,
    error_class: str,
) -> CanonicalSubmissionAttempt:
    """Record SQL-locked recovery proof that dispatch never began."""

    return _append_event(
        attempt,
        state=SubmissionAttemptState.ABANDONED,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        error_class=error_class,
    )


def confirm_submission(
    attempt: CanonicalSubmissionAttempt,
    *,
    occurred_at: datetime,
    recorded_at: datetime,
    response_sha256: str,
    broker_order_id: str,
) -> CanonicalSubmissionAttempt:
    return _append_event(
        attempt,
        state=SubmissionAttemptState.CONFIRMED,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        response_sha256=response_sha256,
        broker_order_id=broker_order_id,
    )


def mark_submission_unknown(
    attempt: CanonicalSubmissionAttempt,
    *,
    occurred_at: datetime,
    recorded_at: datetime,
    error_class: str,
) -> CanonicalSubmissionAttempt:
    return _append_event(
        attempt,
        state=SubmissionAttemptState.UNKNOWN,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        error_class=error_class,
    )


def resolve_unknown_submission(
    attempt: CanonicalSubmissionAttempt,
    *,
    occurred_at: datetime,
    recorded_at: datetime,
    resolution: UnknownSubmissionResolution,
    reconciliation_sha256: str,
    response_sha256: str | None = None,
    broker_order_id: str | None = None,
) -> CanonicalSubmissionAttempt:
    return _append_event(
        attempt,
        state=SubmissionAttemptState.RESOLVED,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        response_sha256=response_sha256,
        broker_order_id=broker_order_id,
        resolution=resolution,
        reconciliation_sha256=reconciliation_sha256,
    )
