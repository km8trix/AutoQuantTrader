from __future__ import annotations

from dataclasses import fields
from decimal import Decimal

import pytest

from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    AlpacaPaperReconciliationConflict,
    AlpacaPaperReconciliationError,
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.domain.broker_reconciliation import (
    BrokerReconciliationOutcome,
)
from tests.unit.test_alpaca_paper_lookup_runtime import (
    OTHER_PROVIDER_ASSET_ID,
    LookupTransport,
    _body_override,
    _fixture,
    _scenario,
)


def _receipt_with(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    **updates: object,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    forged = object.__new__(AlpacaPaperAuthenticatedLookupReceipt)
    for receipt_field in fields(receipt):
        object.__setattr__(
            forged,
            receipt_field.name,
            updates.get(
                receipt_field.name,
                getattr(receipt, receipt_field.name),
            ),
        )
    forged._validate()
    return forged


def _source_with(
    source: PersistedAlpacaClientOrderLookupObservation,
    **updates: object,
) -> PersistedAlpacaClientOrderLookupObservation:
    forged = object.__new__(PersistedAlpacaClientOrderLookupObservation)
    object.__setattr__(forged, "receipt", updates.get("receipt", source.receipt))
    object.__setattr__(
        forged,
        "observation",
        updates.get("observation", source.observation),
    )
    return forged


@pytest.mark.parametrize(
    ("status", "body", "expected_outcome"),
    (
        (
            200,
            _fixture("lookup_found.json"),
            BrokerReconciliationOutcome.ORDER_OBSERVED_CANDIDATE,
        ),
        (
            200,
            _body_override(qty="11"),
            BrokerReconciliationOutcome.QUARANTINED_ECONOMIC_MISMATCH,
        ),
        (
            200,
            _body_override(asset_id=None),
            BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH,
        ),
        (
            404,
            _fixture("lookup_not_found.json"),
            BrokerReconciliationOutcome.INCONCLUSIVE_NOT_VISIBLE,
        ),
    ),
)
def test_authenticated_lookup_outcomes_normalize_without_application_authority(
    status: int,
    body: bytes,
    expected_outcome: BrokerReconciliationOutcome,
) -> None:
    scenario = _scenario(
        transport=LookupTransport(
            status=status,
            body=body,
        )
    )
    receipt = scenario.run()
    source = scenario.lookups.evidence[0].persisted_observation

    evidence = normalize_authenticated_alpaca_paper_lookup(receipt, source)

    assert evidence.outcome is expected_outcome
    assert evidence.source_lookup_receipt_id == receipt.receipt_id
    assert evidence.source_lookup_receipt_sha256 == receipt.semantic_sha256
    assert evidence.source_ingress_receipt_id == source.receipt.receipt_id
    assert evidence.source_ingress_receipt_sha256 == (source.receipt.semantic_sha256)
    assert evidence.source_body_sha256 == source.receipt.delivery.body_sha256
    assert evidence.normalized_fact_authorized is False
    assert evidence.lifecycle_application_authorized is False
    assert evidence.unknown_resolution_authorized is False
    assert evidence.reservation_release_authorized is False
    assert evidence.canonical_execution_fact_authorized is False
    assert evidence.trading_effect_authorized is False

    if status == 404:
        assert evidence.provider_order_id is None
        assert evidence.provider_timestamps == ()
        assert evidence.cumulative_filled_quantity is None
    else:
        assert evidence.provider_order_id == receipt.provider_order_id
        assert evidence.cumulative_filled_quantity == Decimal("0")


def test_normalization_preserves_nanosecond_timestamps_and_cumulative_values() -> None:
    replaced_by = "9449cbfd-f6e8-4e29-9be9-2f47d550abf8"
    replaces = "47fcfab8-12e7-48af-a612-711d9ca1455c"
    scenario = _scenario(
        transport=LookupTransport(
            body=_body_override(
                replaced_by=replaced_by,
                replaces=replaces,
            )
        )
    )
    receipt = scenario.run()

    evidence = normalize_authenticated_alpaca_paper_lookup(
        receipt,
        scenario.lookups.evidence[0].persisted_observation,
    )

    timestamps = {timestamp.field_name: timestamp for timestamp in evidence.provider_timestamps}
    assert timestamps["created_at"].raw == ("2026-07-15T09:31:00.123456789-04:00")
    assert timestamps["created_at"].normalized_utc == ("2026-07-15T13:31:00.123456789Z")
    assert timestamps["created_at"].nanosecond == 123_456_789
    assert timestamps["submitted_at"].nanosecond == 999_999_999
    assert evidence.requested_quantity == Decimal("10")
    assert evidence.requested_notional is None
    assert evidence.cumulative_filled_quantity == Decimal("0")
    assert evidence.cumulative_filled_average_price is None
    assert evidence.provider_replaced_by == replaced_by
    assert evidence.provider_replaces == replaces


@pytest.mark.parametrize(
    ("receipt_update", "message"),
    (
        (
            {"outcome": AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH},
            "economic quarantine",
        ),
        (
            {"provider_order_status": "filled"},
            "provider order status",
        ),
        (
            {"provider_request_id": "different-request"},
            "provider request ID",
        ),
        (
            {"ingress_receipt_sha256": "f" * 64},
            "raw ingress receipt digest",
        ),
    ),
)
def test_receipt_source_substitution_fails_closed(
    receipt_update: dict[str, object],
    message: str,
) -> None:
    scenario = _scenario()
    receipt = scenario.run()
    source = scenario.lookups.evidence[0].persisted_observation
    forged = _receipt_with(receipt, **receipt_update)

    with pytest.raises(AlpacaPaperReconciliationConflict, match=message):
        normalize_authenticated_alpaca_paper_lookup(forged, source)


def test_raw_body_substitution_fails_closed_before_normalization() -> None:
    scenario = _scenario()
    receipt = scenario.run()
    source = scenario.lookups.evidence[0].persisted_observation
    delivery = source.receipt.delivery
    forged_delivery = type(delivery)(
        account_id=delivery.account_id,
        delivery_idempotency_key=delivery.delivery_idempotency_key,
        provider_id=delivery.provider_id,
        adapter_version=delivery.adapter_version,
        environment=delivery.environment,
        channel=delivery.channel,
        operation=delivery.operation,
        received_at=delivery.received_at,
        recorded_at=delivery.recorded_at,
        body=b'{"substituted":true}',
        correlation_sha256=delivery.correlation_sha256,
        transport_status=delivery.transport_status,
        provider_request_id=delivery.provider_request_id,
        media_type=delivery.media_type,
    )
    forged_raw = type(source.receipt)(
        delivery=forged_delivery,
        ingress_sequence=source.receipt.ingress_sequence,
        previous_receipt_sha256=source.receipt.previous_receipt_sha256,
    )
    forged_source = _source_with(source, receipt=forged_raw)

    with pytest.raises(
        AlpacaPaperReconciliationError,
        match=r"conflicts with its raw receipt|source authentication failed",
    ):
        normalize_authenticated_alpaca_paper_lookup(receipt, forged_source)


def test_security_and_economic_mismatch_remain_quarantined_together() -> None:
    scenario = _scenario(
        transport=LookupTransport(
            body=_body_override(
                asset_id=OTHER_PROVIDER_ASSET_ID,
                qty="11",
            )
        )
    )
    receipt = scenario.run()

    evidence = normalize_authenticated_alpaca_paper_lookup(
        receipt,
        scenario.lookups.evidence[0].persisted_observation,
    )

    assert evidence.outcome is BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH
    assert evidence.mismatch_fields == ("quantity",)
    assert evidence.observed_provider_asset_id == OTHER_PROVIDER_ASSET_ID


def test_separate_authenticated_deliveries_remain_separate_historical_sources() -> None:
    first = _scenario()
    second = _scenario()
    first_receipt = first.run(delivery_idempotency_key="phase4k-delivery-a")
    second_receipt = second.run(delivery_idempotency_key="phase4k-delivery-b")

    first_evidence = normalize_authenticated_alpaca_paper_lookup(
        first_receipt,
        first.lookups.evidence[0].persisted_observation,
    )
    second_evidence = normalize_authenticated_alpaca_paper_lookup(
        second_receipt,
        second.lookups.evidence[0].persisted_observation,
    )

    assert first_evidence.provider_order_id == second_evidence.provider_order_id
    assert first_evidence.source_ingress_receipt_id != (second_evidence.source_ingress_receipt_id)
    assert first_evidence.semantic_sha256 != second_evidence.semantic_sha256
