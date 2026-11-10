from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaPaperAccountAssetObservationError,
    create_alpaca_account_observation_description,
    create_alpaca_asset_observation_description,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL,
    ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION,
    ALPACA_PAPER_ASSET_INGRESS_CHANNEL,
    ALPACA_PAPER_ASSET_INGRESS_OPERATION,
    PersistedAlpacaAccountObservation,
    persist_then_decode_alpaca_account_observation_response,
    persist_then_decode_alpaca_asset_observation_response,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
)

ACCOUNT_ID = "paper-account"
RECEIVED_AT = datetime(2024, 1, 2, 15, 4, 6, tzinfo=UTC)
RECORDED_AT = RECEIVED_AT + timedelta(milliseconds=10)


class InMemoryIngressRecorder:
    """A faithful append-only recorder used to observe persistence ordering."""

    def __init__(self) -> None:
        self.deliveries: list[BrokerIngressDelivery] = []
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        previous = self.receipts[-1].semantic_sha256 if self.receipts else None
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=previous,
        )
        self.deliveries.append(delivery)
        self.receipts.append(receipt)
        return receipt


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _account_body() -> bytes:
    return _json_bytes(
        {
            "id": "e6fe16f3-64a4-4921-8928-cadf02f92f98",
            "account_number": "SYNTHETIC01",
            "status": "ACTIVE",
            "currency": "USD",
            "buying_power": "100000.00",
            "cash": "100000.00",
            "portfolio_value": "100000.00",
            "options_buying_power": "0",
            "options_approved_level": 0,
            "options_trading_level": 0,
            "trading_blocked": False,
            "transfers_blocked": False,
            "account_blocked": False,
            "created_at": "2024-01-02T15:04:05.123456789Z",
            "trade_suspended_by_user": False,
            "shorting_enabled": False,
        }
    )


def _asset_body() -> bytes:
    return _json_bytes(
        {
            "id": "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415",
            "class": "us_equity",
            "exchange": "ARCA",
            "symbol": "SPY",
            "name": "SPDR S&P 500 ETF Trust",
            "status": "active",
            "tradable": True,
            "marginable": True,
            "maintenance_margin_requirement": 30,
            "shortable": True,
            "easy_to_borrow": True,
            "fractionable": True,
            "attributes": [],
        }
    )


def test_account_response_is_persisted_before_and_bound_to_decode() -> None:
    recorder = InMemoryIngressRecorder()
    description = create_alpaca_account_observation_description(account_id=ACCOUNT_ID)
    body = _account_body()

    result = persist_then_decode_alpaca_account_observation_response(
        recorder,
        description,
        delivery_idempotency_key="account-delivery-001",
        http_status=200,
        provider_request_id="account-request-001",
        response_body=body,
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )

    assert recorder.receipts == [result.receipt]
    assert result.receipt.delivery == recorder.deliveries[0]
    assert result.receipt.delivery.account_id == ACCOUNT_ID
    assert result.receipt.delivery.provider_id == ALPACA_PAPER_ADAPTER_ID
    assert result.receipt.delivery.adapter_version == ALPACA_PAPER_ADAPTER_VERSION
    assert result.receipt.delivery.environment == "paper"
    assert result.receipt.delivery.channel == ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL
    assert result.receipt.delivery.operation == ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION
    assert result.receipt.delivery.correlation_sha256 == description.semantic_sha256
    assert result.receipt.delivery.transport_status == result.observation.http_status == 200
    assert (
        result.receipt.delivery.provider_request_id
        == result.observation.provider_request_id
        == "account-request-001"
    )
    assert result.receipt.delivery.received_at == result.observation.received_at == RECEIVED_AT
    assert result.receipt.delivery.recorded_at == RECORDED_AT
    assert result.receipt.delivery.body == result.observation.response_body == body
    assert result.receipt.delivery.body_sha256 == result.observation.response_sha256
    assert result.normalized_fact_authorized is False
    assert result.lifecycle_application_authorized is False
    assert result.canonical_execution_fact_authorized is False
    assert result.runtime_current is False
    assert result.authenticated_provider_evidence is False
    assert result.economics_canonicalized is False
    assert result.durable_account_binding_authorized is False
    assert result.canonical_account_fact_authorized is False
    assert result.dispatch_preflight_ready is False
    assert result.trading_effect_authorized is False


def test_asset_response_is_persisted_before_and_bound_to_decode() -> None:
    recorder = InMemoryIngressRecorder()
    description = create_alpaca_asset_observation_description(
        account_id=ACCOUNT_ID,
        instrument_id="US-ETF-SPY",
        symbol="SPY",
    )
    body = _asset_body()

    result = persist_then_decode_alpaca_asset_observation_response(
        recorder,
        description,
        delivery_idempotency_key="asset-delivery-001",
        http_status=200,
        provider_request_id="asset-request-001",
        response_body=body,
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )

    assert recorder.receipts == [result.receipt]
    assert result.receipt.delivery.channel == ALPACA_PAPER_ASSET_INGRESS_CHANNEL
    assert result.receipt.delivery.operation == ALPACA_PAPER_ASSET_INGRESS_OPERATION
    assert result.receipt.delivery.correlation_sha256 == description.semantic_sha256
    assert result.receipt.delivery.transport_status == result.observation.http_status == 200
    assert result.receipt.delivery.provider_request_id == result.observation.provider_request_id
    assert result.receipt.delivery.received_at == result.observation.received_at
    assert result.receipt.delivery.body == result.observation.response_body == body
    assert result.receipt.delivery.body_sha256 == result.observation.response_sha256
    assert result.normalized_fact_authorized is False
    assert result.lifecycle_application_authorized is False
    assert result.canonical_execution_fact_authorized is False
    assert result.runtime_current is False
    assert result.authenticated_provider_evidence is False
    assert result.durable_security_identity_binding_authorized is False
    assert result.security_mapping_ready is False
    assert result.asset_tradability_validation_ready is False
    assert result.fractional_quantity_authorized is False
    assert result.short_exposure_authorized is False
    assert result.dispatch_preflight_ready is False
    assert result.trading_effect_authorized is False


@pytest.mark.parametrize("kind", ["account", "asset"])
def test_decode_failure_cannot_erase_raw_account_or_asset_delivery(kind: str) -> None:
    recorder = InMemoryIngressRecorder()
    malformed = b'{"unreviewed_additive_field":true}'

    with pytest.raises(AlpacaPaperAccountAssetObservationError):
        if kind == "account":
            persist_then_decode_alpaca_account_observation_response(
                recorder,
                create_alpaca_account_observation_description(account_id=ACCOUNT_ID),
                delivery_idempotency_key="account-malformed",
                http_status=200,
                provider_request_id="account-malformed-request",
                response_body=malformed,
                received_at=RECEIVED_AT,
                recorded_at=RECORDED_AT,
            )
        else:
            persist_then_decode_alpaca_asset_observation_response(
                recorder,
                create_alpaca_asset_observation_description(
                    account_id=ACCOUNT_ID,
                    instrument_id="US-ETF-SPY",
                    symbol="SPY",
                ),
                delivery_idempotency_key="asset-malformed",
                http_status=200,
                provider_request_id="asset-malformed-request",
                response_body=malformed,
                received_at=RECEIVED_AT,
                recorded_at=RECORDED_AT,
            )

    assert len(recorder.receipts) == 1
    assert recorder.receipts[0].delivery.body == malformed
    assert recorder.receipts[0].ingress_sequence == 1
    assert recorder.receipts[0].normalized_fact_authorized is False
    assert recorder.receipts[0].trading_effect_authorized is False


def test_mismatched_recorder_receipt_fails_before_asset_decode() -> None:
    class MismatchedRecorder:
        def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
            return BrokerIngressReceipt(
                delivery=replace(delivery, body=b"different-persisted-bytes"),
                ingress_sequence=1,
                previous_receipt_sha256=None,
            )

    with pytest.raises(BrokerIngressError, match="different Alpaca asset bytes"):
        persist_then_decode_alpaca_asset_observation_response(
            MismatchedRecorder(),
            create_alpaca_asset_observation_description(
                account_id=ACCOUNT_ID,
                instrument_id="US-ETF-SPY",
                symbol="SPY",
            ),
            delivery_idempotency_key="asset-mismatched-recorder",
            http_status=200,
            provider_request_id="asset-mismatched-request",
            response_body=b'{"would_fail":"if_decoded"}',
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )


_RECEIPT_MUTATIONS: tuple[
    Callable[[BrokerIngressDelivery], BrokerIngressDelivery],
    ...,
] = (
    lambda delivery: replace(delivery, account_id="different-account"),
    lambda delivery: replace(delivery, provider_id="different-provider"),
    lambda delivery: replace(delivery, adapter_version="different-version"),
    lambda delivery: replace(delivery, environment="live"),
    lambda delivery: replace(delivery, channel="different-channel"),
    lambda delivery: replace(delivery, operation="different-operation"),
    lambda delivery: replace(delivery, correlation_sha256="f" * 64),
    lambda delivery: replace(delivery, transport_status=201),
    lambda delivery: replace(delivery, provider_request_id="different-request"),
    lambda delivery: replace(
        delivery,
        received_at=RECEIVED_AT - timedelta(seconds=1),
    ),
    lambda delivery: replace(delivery, body=b"different-body"),
)


@pytest.mark.parametrize("mutate_delivery", _RECEIPT_MUTATIONS)
def test_persisted_account_observation_rejects_receipt_mismatch(
    mutate_delivery: Callable[[BrokerIngressDelivery], BrokerIngressDelivery],
) -> None:
    recorder = InMemoryIngressRecorder()
    result = persist_then_decode_alpaca_account_observation_response(
        recorder,
        create_alpaca_account_observation_description(account_id=ACCOUNT_ID),
        delivery_idempotency_key="account-valid-before-tamper",
        http_status=200,
        provider_request_id="account-valid-request",
        response_body=_account_body(),
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )
    mismatched_delivery = mutate_delivery(result.receipt.delivery)
    mismatched_receipt = BrokerIngressReceipt(
        delivery=mismatched_delivery,
        ingress_sequence=1,
        previous_receipt_sha256=None,
    )

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="conflicts with its raw receipt",
    ):
        PersistedAlpacaAccountObservation(
            receipt=mismatched_receipt,
            observation=result.observation,
        )
