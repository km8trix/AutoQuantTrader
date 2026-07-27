from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from packages.domain.broker_ingress import (
    MAX_BROKER_INGRESS_BODY_BYTES,
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
)

RECEIVED_AT = datetime(2026, 7, 26, 14, 0, tzinfo=UTC)
RECORDED_AT = RECEIVED_AT + timedelta(milliseconds=5)


def delivery(**overrides: object) -> BrokerIngressDelivery:
    values: dict[str, object] = {
        "account_id": "paper-account",
        "delivery_idempotency_key": "lookup-attempt-001",
        "provider_id": "alpaca",
        "adapter_version": "1.0.0",
        "environment": "paper",
        "channel": "trading-rest",
        "operation": "get-order-by-client-order-id",
        "correlation_sha256": "a" * 64,
        "transport_status": 200,
        "provider_request_id": "request-001",
        "media_type": "application/json",
        "received_at": RECEIVED_AT,
        "recorded_at": RECORDED_AT,
        "body": b'{"id":"provider-order-1"}',
    }
    values.update(overrides)
    return BrokerIngressDelivery(**values)  # type: ignore[arg-type]


def test_delivery_derives_exact_body_and_semantic_digests() -> None:
    first = delivery()
    exact_copy = delivery()

    assert first == exact_copy
    assert first.body_size_bytes == len(first.body)
    assert first.body_sha256 == exact_copy.body_sha256
    assert first.receipt_id == exact_copy.receipt_id
    assert first.semantic_sha256 == exact_copy.semantic_sha256
    assert len(first.body_sha256) == len(first.receipt_id) == 64


def test_delivery_identity_is_stable_but_content_digest_detects_conflicts() -> None:
    original = delivery()
    conflicting = delivery(body=b'{"id":"different-provider-order"}')

    assert conflicting.receipt_id == original.receipt_id
    assert conflicting.body_sha256 != original.body_sha256
    assert conflicting.semantic_sha256 != original.semantic_sha256


def test_distinct_delivery_keys_preserve_duplicate_transport_bodies() -> None:
    first = delivery(delivery_idempotency_key="lookup-attempt-001")
    second = delivery(delivery_idempotency_key="lookup-attempt-002")

    assert first.body == second.body
    assert first.body_sha256 == second.body_sha256
    assert first.receipt_id != second.receipt_id
    assert first.semantic_sha256 != second.semantic_sha256


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "message"),
    (
        ("account_id", "", "account ID"),
        ("account_id", " paper-account", "account ID"),
        ("account_id", "x" * 65, "account ID"),
        ("delivery_idempotency_key", "key\ninjection", "idempotency key"),
        ("provider_id", 1, "provider ID"),
        ("adapter_version", "", "adapter version"),
        ("adapter_version", "x" * 65, "adapter version"),
        ("environment", "x" * 33, "environment"),
        ("channel", "", "channel"),
        ("operation", "lookup\x7f", "operation"),
    ),
)
def test_delivery_rejects_invalid_required_text(
    field_name: str,
    invalid_value: object,
    message: str,
) -> None:
    with pytest.raises(BrokerIngressError, match=message):
        delivery(**{field_name: invalid_value})


@pytest.mark.parametrize("transport_status", (True, 99, 600, "200"))
def test_delivery_rejects_invalid_transport_status(transport_status: object) -> None:
    with pytest.raises(BrokerIngressError, match="transport status"):
        delivery(transport_status=transport_status)


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "message"),
    (
        ("correlation_sha256", "A" * 64, "correlation digest"),
        ("correlation_sha256", "a" * 63, "correlation digest"),
        ("provider_request_id", "request\nid", "provider request ID"),
        ("provider_request_id", "x" * 257, "provider request ID"),
        ("media_type", "application/json\x00", "media type"),
        ("media_type", "x" * 129, "media type"),
    ),
)
def test_delivery_rejects_invalid_optional_transport_metadata(
    field_name: str,
    invalid_value: object,
    message: str,
) -> None:
    with pytest.raises(BrokerIngressError, match=message):
        delivery(**{field_name: invalid_value})


def test_delivery_preserves_empty_untrimmed_transport_metadata() -> None:
    observed = delivery(provider_request_id="", media_type=" application/octet-stream ")

    assert observed.provider_request_id == ""
    assert observed.media_type == " application/octet-stream "


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "message"),
    (
        ("received_at", RECEIVED_AT.replace(tzinfo=None), "received_at must be timezone-aware"),
        (
            "received_at",
            RECEIVED_AT.astimezone(timezone(timedelta(hours=-4))),
            "received_at must be UTC",
        ),
        ("recorded_at", "2026-07-26T14:00:00Z", "recorded_at must be an exact datetime"),
        (
            "recorded_at",
            RECEIVED_AT - timedelta(microseconds=1),
            "recorded_at cannot precede",
        ),
    ),
)
def test_delivery_rejects_invalid_capture_times(
    field_name: str,
    invalid_value: object,
    message: str,
) -> None:
    with pytest.raises(BrokerIngressError, match=message):
        delivery(**{field_name: invalid_value})


def test_delivery_requires_exact_bounded_bytes_but_accepts_empty_bytes() -> None:
    assert delivery(body=b"").body == b""

    with pytest.raises(BrokerIngressError, match="body must be exact bytes"):
        delivery(body=bytearray(b"mutable"))
    with pytest.raises(BrokerIngressError, match="exceeds the durable capture bound"):
        delivery(body=b"x" * (MAX_BROKER_INGRESS_BODY_BYTES + 1))


def test_receipt_enforces_sequence_and_predecessor_shape() -> None:
    first = BrokerIngressReceipt(
        delivery=delivery(),
        ingress_sequence=1,
        previous_receipt_sha256=None,
    )
    second = BrokerIngressReceipt(
        delivery=delivery(delivery_idempotency_key="lookup-attempt-002"),
        ingress_sequence=2,
        previous_receipt_sha256=first.semantic_sha256,
    )

    assert first.previous_receipt_sha256 is None
    assert second.previous_receipt_sha256 == first.semantic_sha256
    assert first.semantic_sha256 != second.semantic_sha256

    with pytest.raises(BrokerIngressError, match="positive integer"):
        BrokerIngressReceipt(delivery=delivery(), ingress_sequence=0, previous_receipt_sha256=None)
    with pytest.raises(BrokerIngressError, match=r"first .* cannot have a predecessor"):
        BrokerIngressReceipt(
            delivery=delivery(),
            ingress_sequence=1,
            previous_receipt_sha256="a" * 64,
        )
    with pytest.raises(BrokerIngressError, match=r"later .* require a predecessor"):
        BrokerIngressReceipt(
            delivery=delivery(),
            ingress_sequence=2,
            previous_receipt_sha256=None,
        )
    with pytest.raises(BrokerIngressError, match="lowercase SHA-256"):
        BrokerIngressReceipt(
            delivery=delivery(),
            ingress_sequence=2,
            previous_receipt_sha256="A" * 64,
        )


def test_receipt_rejects_delivery_subclasses_and_is_immutable() -> None:
    class DeliverySubclass(BrokerIngressDelivery):
        pass

    subclass = DeliverySubclass(
        account_id="paper-account",
        delivery_idempotency_key="lookup-attempt-001",
        provider_id="alpaca",
        adapter_version="1.0.0",
        environment="paper",
        channel="trading-rest",
        operation="lookup",
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
        body=b"{}",
    )
    with pytest.raises(BrokerIngressError, match="exact BrokerIngressDelivery"):
        BrokerIngressReceipt(
            delivery=subclass,
            ingress_sequence=1,
            previous_receipt_sha256=None,
        )

    receipt = BrokerIngressReceipt(
        delivery=delivery(),
        ingress_sequence=1,
        previous_receipt_sha256=None,
    )
    with pytest.raises(FrozenInstanceError):
        receipt.ingress_sequence = 2  # type: ignore[misc]


def test_raw_receipt_grants_no_downstream_or_trading_authority() -> None:
    receipt = BrokerIngressReceipt(
        delivery=delivery(),
        ingress_sequence=1,
        previous_receipt_sha256=None,
    )

    assert receipt.normalized_fact_authorized is False
    assert receipt.lifecycle_application_authorized is False
    assert receipt.canonical_execution_fact_authorized is False
    assert receipt.trading_effect_authorized is False


def test_receipt_revalidates_a_tampered_nested_delivery() -> None:
    source = delivery()
    object.__setattr__(source, "body", bytearray(b"tampered"))

    with pytest.raises(BrokerIngressError, match="body must be exact bytes"):
        BrokerIngressReceipt(
            delivery=source,
            ingress_sequence=1,
            previous_receipt_sha256=None,
        )


def test_replace_exposes_same_delivery_identity_for_a_conflicting_retry() -> None:
    source = delivery()
    conflicting = replace(source, transport_status=404, body=b'{"code":40410000}')

    assert conflicting.receipt_id == source.receipt_id
    assert conflicting.semantic_sha256 != source.semantic_sha256
