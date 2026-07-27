"""Persist-first adapter boundary for offline Alpaca lookup responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
)
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaClientOrderLookupDescription,
    AlpacaClientOrderLookupObservation,
    AlpacaPaperObservationError,
    decode_alpaca_client_order_lookup_response,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
    BrokerIngressRecorder,
)

ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL = "rest_lookup_response"
ALPACA_PAPER_LOOKUP_INGRESS_OPERATION = "get_order_by_client_order_id"


@dataclass(frozen=True, slots=True)
class PersistedAlpacaClientOrderLookupObservation:
    """A decoded observation bound to the raw receipt committed before it."""

    receipt: BrokerIngressReceipt
    observation: AlpacaClientOrderLookupObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperObservationError(
                "persisted lookup observation requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaClientOrderLookupObservation:
            raise AlpacaPaperObservationError(
                "persisted lookup observation requires an exact Alpaca observation"
            )
        self.receipt.__post_init__()
        self.observation.__post_init__()
        delivery = self.receipt.delivery
        observation = self.observation
        expected = (
            (delivery.account_id, observation.description.account_id),
            (delivery.provider_id, ALPACA_PAPER_ADAPTER_ID),
            (delivery.adapter_version, ALPACA_PAPER_ADAPTER_VERSION),
            (delivery.environment, "paper"),
            (delivery.channel, ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL),
            (delivery.operation, ALPACA_PAPER_LOOKUP_INGRESS_OPERATION),
            (
                delivery.correlation_sha256,
                observation.description.semantic_sha256,
            ),
            (delivery.transport_status, observation.http_status),
            (delivery.provider_request_id, observation.provider_request_id),
            (delivery.received_at, observation.received_at),
            (delivery.body, observation.response_body),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise AlpacaPaperObservationError(
                "decoded Alpaca lookup observation conflicts with its raw receipt"
            )

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def persist_then_decode_alpaca_client_order_lookup_response(
    recorder: BrokerIngressRecorder,
    description: AlpacaClientOrderLookupDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaClientOrderLookupObservation:
    """Commit exact response bytes, then run the Phase 4B offline decoder.

    A typed decoder failure is intentionally allowed to escape.  The raw
    receipt has already committed in its own repository transaction and remains
    available for inspection or a later reviewed decoder version.
    """

    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError("Alpaca lookup ingress requires a durable recorder")
    if type(description) is not AlpacaClientOrderLookupDescription:
        raise AlpacaPaperObservationError(
            "Alpaca lookup ingress requires an exact lookup description"
        )
    description.__post_init__()
    delivery = BrokerIngressDelivery(
        account_id=description.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
        correlation_sha256=description.semantic_sha256,
        transport_status=http_status,
        provider_request_id=provider_request_id,
        media_type=media_type,
        received_at=received_at,
        recorded_at=recorded_at,
        body=response_body,
    )
    receipt = recorder.record(delivery)
    if type(receipt) is not BrokerIngressReceipt:
        raise BrokerIngressError(
            "durable recorder returned an invalid Alpaca lookup ingress receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError(
            "durable recorder returned a receipt for different Alpaca lookup bytes"
        )
    observation = decode_alpaca_client_order_lookup_response(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaClientOrderLookupObservation(
        receipt=receipt,
        observation=observation,
    )


__all__ = [
    "ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL",
    "ALPACA_PAPER_LOOKUP_INGRESS_OPERATION",
    "PersistedAlpacaClientOrderLookupObservation",
    "persist_then_decode_alpaca_client_order_lookup_response",
]
