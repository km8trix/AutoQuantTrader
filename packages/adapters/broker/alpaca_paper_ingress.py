"""Persist-first adapter boundary for offline Alpaca paper responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAccountObservation,
    AlpacaAssetObservation,
    AlpacaPaperAccountAssetObservationError,
    AlpacaPaperAccountObservationDescription,
    AlpacaPaperAssetObservationDescription,
    decode_alpaca_account_observation_response,
    decode_alpaca_asset_observation_response,
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
ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL = "rest_account_response"
ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION = "get_account"
ALPACA_PAPER_ASSET_INGRESS_CHANNEL = "rest_asset_response"
ALPACA_PAPER_ASSET_INGRESS_OPERATION = "get_asset_by_symbol"


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


def _validate_account_asset_receipt_binding(
    receipt: BrokerIngressReceipt,
    *,
    account_id: str,
    correlation_sha256: str,
    channel: str,
    operation: str,
    http_status: int,
    provider_request_id: str,
    received_at: datetime,
    response_body: bytes,
    response_sha256: str,
    observation_kind: str,
) -> None:
    delivery = receipt.delivery
    expected = (
        (delivery.account_id, account_id),
        (delivery.provider_id, ALPACA_PAPER_ADAPTER_ID),
        (delivery.adapter_version, ALPACA_PAPER_ADAPTER_VERSION),
        (delivery.environment, "paper"),
        (delivery.channel, channel),
        (delivery.operation, operation),
        (delivery.correlation_sha256, correlation_sha256),
        (delivery.transport_status, http_status),
        (delivery.provider_request_id, provider_request_id),
        (delivery.received_at, received_at),
        (delivery.body, response_body),
        (delivery.body_sha256, response_sha256),
    )
    if any(actual != wanted for actual, wanted in expected):
        raise AlpacaPaperAccountAssetObservationError(
            f"decoded Alpaca {observation_kind} observation conflicts with its raw receipt"
        )


@dataclass(frozen=True, slots=True)
class PersistedAlpacaAccountObservation:
    """A decoded account observation bound to the raw receipt committed before it."""

    receipt: BrokerIngressReceipt
    observation: AlpacaAccountObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperAccountAssetObservationError(
                "persisted account observation requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaAccountObservation:
            raise AlpacaPaperAccountAssetObservationError(
                "persisted account observation requires an exact Alpaca observation"
            )
        self.receipt.__post_init__()
        self.observation.__post_init__()
        observation = self.observation
        _validate_account_asset_receipt_binding(
            self.receipt,
            account_id=observation.description.account_id,
            correlation_sha256=observation.description.semantic_sha256,
            channel=ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL,
            operation=ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION,
            http_status=observation.http_status,
            provider_request_id=observation.provider_request_id,
            received_at=observation.received_at,
            response_body=observation.response_body,
            response_sha256=observation.response_sha256,
            observation_kind="account",
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
    def runtime_current(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def economics_canonicalized(self) -> bool:
        return False

    @property
    def durable_account_binding_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class PersistedAlpacaAssetObservation:
    """A decoded asset observation bound to the raw receipt committed before it."""

    receipt: BrokerIngressReceipt
    observation: AlpacaAssetObservation

    def __post_init__(self) -> None:
        if type(self.receipt) is not BrokerIngressReceipt:
            raise AlpacaPaperAccountAssetObservationError(
                "persisted asset observation requires an exact ingress receipt"
            )
        if type(self.observation) is not AlpacaAssetObservation:
            raise AlpacaPaperAccountAssetObservationError(
                "persisted asset observation requires an exact Alpaca observation"
            )
        self.receipt.__post_init__()
        self.observation.__post_init__()
        observation = self.observation
        _validate_account_asset_receipt_binding(
            self.receipt,
            account_id=observation.description.account_id,
            correlation_sha256=observation.description.semantic_sha256,
            channel=ALPACA_PAPER_ASSET_INGRESS_CHANNEL,
            operation=ALPACA_PAPER_ASSET_INGRESS_OPERATION,
            http_status=observation.http_status,
            provider_request_id=observation.provider_request_id,
            received_at=observation.received_at,
            response_body=observation.response_body,
            response_sha256=observation.response_sha256,
            observation_kind="asset",
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
    def runtime_current(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def durable_security_identity_binding_authorized(self) -> bool:
        return False

    @property
    def security_mapping_ready(self) -> bool:
        return False

    @property
    def asset_tradability_validation_ready(self) -> bool:
        return False

    @property
    def fractional_quantity_authorized(self) -> bool:
        return False

    @property
    def short_exposure_authorized(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _record_alpaca_account_asset_delivery(
    recorder: BrokerIngressRecorder,
    *,
    account_id: str,
    delivery_idempotency_key: str,
    correlation_sha256: str,
    channel: str,
    operation: str,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None,
    observation_kind: str,
) -> BrokerIngressReceipt:
    if not callable(getattr(recorder, "record", None)):
        raise BrokerIngressError(f"Alpaca {observation_kind} ingress requires a durable recorder")
    delivery = BrokerIngressDelivery(
        account_id=account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        adapter_version=ALPACA_PAPER_ADAPTER_VERSION,
        environment="paper",
        channel=channel,
        operation=operation,
        correlation_sha256=correlation_sha256,
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
            f"durable recorder returned an invalid Alpaca {observation_kind} ingress receipt"
        )
    receipt.__post_init__()
    if receipt.delivery != delivery:
        raise BrokerIngressError(
            f"durable recorder returned a receipt for different Alpaca {observation_kind} bytes"
        )
    return receipt


def persist_then_decode_alpaca_account_observation_response(
    recorder: BrokerIngressRecorder,
    description: AlpacaPaperAccountObservationDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaAccountObservation:
    """Commit an exact account response before running its offline decoder."""

    if type(description) is not AlpacaPaperAccountObservationDescription:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account ingress requires an exact account observation description"
        )
    description.__post_init__()
    receipt = _record_alpaca_account_asset_delivery(
        recorder,
        account_id=description.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        correlation_sha256=description.semantic_sha256,
        channel=ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
        recorded_at=recorded_at,
        media_type=media_type,
        observation_kind="account",
    )
    if provider_request_id is None:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account response is missing X-Request-ID after raw persistence"
        )
    observation = decode_alpaca_account_observation_response(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaAccountObservation(
        receipt=receipt,
        observation=observation,
    )


def persist_then_decode_alpaca_asset_observation_response(
    recorder: BrokerIngressRecorder,
    description: AlpacaPaperAssetObservationDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
    received_at: datetime,
    recorded_at: datetime,
    media_type: str | None = "application/json",
) -> PersistedAlpacaAssetObservation:
    """Commit an exact asset response before running its offline decoder."""

    if type(description) is not AlpacaPaperAssetObservationDescription:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset ingress requires an exact asset observation description"
        )
    description.__post_init__()
    receipt = _record_alpaca_account_asset_delivery(
        recorder,
        account_id=description.account_id,
        delivery_idempotency_key=delivery_idempotency_key,
        correlation_sha256=description.semantic_sha256,
        channel=ALPACA_PAPER_ASSET_INGRESS_CHANNEL,
        operation=ALPACA_PAPER_ASSET_INGRESS_OPERATION,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
        recorded_at=recorded_at,
        media_type=media_type,
        observation_kind="asset",
    )
    if provider_request_id is None:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset response is missing X-Request-ID after raw persistence"
        )
    observation = decode_alpaca_asset_observation_response(
        description,
        http_status=http_status,
        provider_request_id=provider_request_id,
        response_body=response_body,
        received_at=received_at,
    )
    return PersistedAlpacaAssetObservation(
        receipt=receipt,
        observation=observation,
    )


def persist_then_decode_alpaca_client_order_lookup_response(
    recorder: BrokerIngressRecorder,
    description: AlpacaClientOrderLookupDescription,
    *,
    delivery_idempotency_key: str,
    http_status: int,
    provider_request_id: str | None,
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
    if provider_request_id is None:
        raise AlpacaPaperObservationError(
            "Alpaca lookup response is missing X-Request-ID after raw persistence"
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
    "ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL",
    "ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION",
    "ALPACA_PAPER_ASSET_INGRESS_CHANNEL",
    "ALPACA_PAPER_ASSET_INGRESS_OPERATION",
    "ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL",
    "ALPACA_PAPER_LOOKUP_INGRESS_OPERATION",
    "PersistedAlpacaAccountObservation",
    "PersistedAlpacaAssetObservation",
    "PersistedAlpacaClientOrderLookupObservation",
    "persist_then_decode_alpaca_account_observation_response",
    "persist_then_decode_alpaca_asset_observation_response",
    "persist_then_decode_alpaca_client_order_lookup_response",
]
