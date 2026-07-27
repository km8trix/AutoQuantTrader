"""Provider-neutral contracts for durable, pre-decode broker ingress.

The values in this module describe exact transport deliveries and their local
append-only receipts.  They do not decode provider payloads, establish provider
event identity, mutate an order lifecycle, or grant broker authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from packages.domain.canonical import canonical_json_bytes
from packages.domain.models import require_utc

BROKER_INGRESS_CONTRACT_VERSION = "phase4c-broker-ingress-v1"
MAX_BROKER_INGRESS_BODY_BYTES = 1_048_576


class BrokerIngressError(ValueError):
    """A broker ingress delivery or receipt violates the durable contract."""


class BrokerIngressConflict(BrokerIngressError):
    """A durable delivery identity already has different immutable content."""


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
    allow_empty: bool = False,
    require_trimmed: bool = True,
) -> str:
    if type(value) is not str:
        raise BrokerIngressError(f"{field_name} must be an exact string")
    if (
        len(value) > maximum
        or (not allow_empty and not value)
        or (require_trimmed and value != value.strip())
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerIngressError(f"{field_name} contains unsupported text")
    return value


def _require_optional_transport_text(
    value: object,
    field_name: str,
    *,
    maximum: int,
) -> str | None:
    if value is None:
        return None
    return _require_text(
        value,
        field_name,
        maximum=maximum,
        allow_empty=True,
        require_trimmed=False,
    )


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BrokerIngressError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name)


def _require_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise BrokerIngressError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise BrokerIngressError(str(error)) from error
    return value


@dataclass(frozen=True, slots=True)
class BrokerIngressDelivery:
    """One exact transport delivery to retain before provider decoding.

    ``delivery_idempotency_key`` is assigned by the transport boundary.  An
    exact retry reuses it; a separate delivery uses a new key even when the
    response bytes happen to be identical.
    """

    account_id: str
    delivery_idempotency_key: str
    provider_id: str
    adapter_version: str
    environment: str
    channel: str
    operation: str
    received_at: datetime
    recorded_at: datetime
    body: bytes = field(repr=False)
    correlation_sha256: str | None = None
    transport_status: int | None = None
    provider_request_id: str | None = None
    media_type: str | None = None

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "broker ingress account ID", 64),
            (
                self.delivery_idempotency_key,
                "broker ingress delivery idempotency key",
                128,
            ),
            (self.provider_id, "broker ingress provider ID", 128),
            (self.adapter_version, "broker ingress adapter version", 64),
            (self.environment, "broker ingress environment", 32),
            (self.channel, "broker ingress channel", 128),
            (self.operation, "broker ingress operation", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        _require_optional_sha256(
            self.correlation_sha256,
            "broker ingress correlation digest",
        )
        if self.transport_status is not None and (
            type(self.transport_status) is not int or not 100 <= self.transport_status <= 599
        ):
            raise BrokerIngressError(
                "broker ingress transport status must be an HTTP status or null"
            )
        _require_optional_transport_text(
            self.provider_request_id,
            "broker ingress provider request ID",
            maximum=256,
        )
        _require_optional_transport_text(
            self.media_type,
            "broker ingress media type",
            maximum=128,
        )
        received_at = _require_utc(self.received_at, "broker ingress received_at")
        recorded_at = _require_utc(self.recorded_at, "broker ingress recorded_at")
        if recorded_at < received_at:
            raise BrokerIngressError("broker ingress recorded_at cannot precede received_at")
        if type(self.body) is not bytes:
            raise BrokerIngressError("broker ingress body must be exact bytes")
        if len(self.body) > MAX_BROKER_INGRESS_BODY_BYTES:
            raise BrokerIngressError("broker ingress body exceeds the durable capture bound")

    @property
    def body_size_bytes(self) -> int:
        return len(self.body)

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def receipt_id(self) -> str:
        """Stable identity for exact retry detection before sequence allocation."""

        return _semantic_sha256(
            (
                BROKER_INGRESS_CONTRACT_VERSION,
                "receipt_identity",
                self.account_id,
                self.delivery_idempotency_key,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BROKER_INGRESS_CONTRACT_VERSION,
                "delivery",
                self.account_id,
                self.delivery_idempotency_key,
                self.provider_id,
                self.adapter_version,
                self.environment,
                self.channel,
                self.operation,
                self.correlation_sha256,
                self.transport_status,
                self.provider_request_id,
                self.media_type,
                self.received_at,
                self.recorded_at,
                self.body_size_bytes,
                self.body_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class BrokerIngressReceipt:
    """One immutable account-local append-only raw ingress receipt."""

    delivery: BrokerIngressDelivery
    ingress_sequence: int
    previous_receipt_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.delivery) is not BrokerIngressDelivery:
            raise BrokerIngressError(
                "broker ingress receipt requires an exact BrokerIngressDelivery"
            )
        self.delivery.__post_init__()
        if type(self.ingress_sequence) is not int or self.ingress_sequence <= 0:
            raise BrokerIngressError("broker ingress sequence must be a positive integer")
        if self.ingress_sequence == 1:
            if self.previous_receipt_sha256 is not None:
                raise BrokerIngressError("first broker ingress receipt cannot have a predecessor")
        else:
            if self.previous_receipt_sha256 is None:
                raise BrokerIngressError("later broker ingress receipts require a predecessor")
            _require_sha256(
                self.previous_receipt_sha256,
                "broker ingress predecessor digest",
            )

    @property
    def receipt_id(self) -> str:
        return self.delivery.receipt_id

    @property
    def account_id(self) -> str:
        return self.delivery.account_id

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                BROKER_INGRESS_CONTRACT_VERSION,
                "receipt",
                self.receipt_id,
                self.delivery.semantic_sha256,
                self.ingress_sequence,
                self.previous_receipt_sha256,
            )
        )

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


class BrokerIngressRecorder(Protocol):
    """Minimal port that guarantees a raw receipt is durable on return."""

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        """Commit one exact delivery or return its identical durable retry."""


__all__ = [
    "BROKER_INGRESS_CONTRACT_VERSION",
    "MAX_BROKER_INGRESS_BODY_BYTES",
    "BrokerIngressConflict",
    "BrokerIngressDelivery",
    "BrokerIngressError",
    "BrokerIngressReceipt",
    "BrokerIngressRecorder",
]
