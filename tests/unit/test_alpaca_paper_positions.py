from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAssetClass,
    AlpacaAssetExchange,
)
from packages.adapters.broker.alpaca_paper_positions import (
    ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL,
    ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION,
    ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS,
    AlpacaPaperPositionDecimal,
    AlpacaPaperPositionObservation,
    AlpacaPaperPositionSide,
    AlpacaPaperPositionSnapshotDescription,
    AlpacaPaperPositionSnapshotError,
    AlpacaPaperPositionSnapshotObservation,
    PersistedAlpacaPaperPositionSnapshot,
    create_alpaca_paper_position_snapshot_description,
    decode_alpaca_paper_position_snapshot_response,
    persist_then_decode_alpaca_paper_position_snapshot_response,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressError,
    BrokerIngressReceipt,
)

ACCOUNT_ID = "paper-account-positions"
CAPTURE_KEY = "position-capture-0001"
RECEIVED_AT = datetime(2026, 7, 28, 18, 30, tzinfo=UTC)
RECORDED_AT = RECEIVED_AT + timedelta(milliseconds=2)


class _Recorder:
    def __init__(self) -> None:
        self.deliveries: list[BrokerIngressDelivery] = []
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        self.deliveries.append(delivery)
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=(
                None if not self.receipts else self.receipts[-1].semantic_sha256
            ),
        )
        self.receipts.append(receipt)
        return receipt


def _description() -> AlpacaPaperPositionSnapshotDescription:
    return create_alpaca_paper_position_snapshot_description(
        account_id=ACCOUNT_ID,
        capture_idempotency_key=CAPTURE_KEY,
    )


def _position(
    number: int,
    *,
    symbol: str = "SPY",
    side: str = "long",
) -> dict[str, object]:
    short = side == "short"
    return {
        "asset_id": str(UUID(int=number)),
        "symbol": symbol,
        "exchange": "ARCA",
        "asset_class": "us_equity",
        "asset_marginable": True,
        "avg_entry_price": "430.1200",
        "qty": "-2.5000" if short else "2.5000",
        "side": side,
        "market_value": "-1077.80000" if short else "1077.80000",
        "cost_basis": "-1075.3000" if short else "1075.3000",
        "unrealized_pl": "-2.50000" if short else "2.50000",
        "unrealized_plpc": "-0.002325" if short else "0.002325",
        "unrealized_intraday_pl": "-1.2500" if short else "1.2500",
        "unrealized_intraday_plpc": "-0.001161" if short else "0.001161",
        "current_price": "431.120000",
        "lastday_price": "430.6200",
        "change_today": "0.001161",
        "qty_available": "-1.500" if short else "1.500",
    }


def _body(*positions: dict[str, object]) -> bytes:
    return json.dumps(
        positions,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _persist(
    recorder: _Recorder,
    body: bytes,
    *,
    request_id: str | None = "position-request-0001",
) -> PersistedAlpacaPaperPositionSnapshot:
    return persist_then_decode_alpaca_paper_position_snapshot_response(
        recorder,
        _description(),
        http_status=200,
        provider_request_id=request_id,
        response_body=body,
        received_at=RECEIVED_AT,
        recorded_at=RECORDED_AT,
    )


def _assert_no_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "runtime_current",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "converged",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "canonical_position_fact_authorized",
        "canonical_execution_fact_authorized",
        "canonical_account_fact_authorized",
        "canonical_ledger_fact_authorized",
        "canonical_cash_fact_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "readiness_transition_authorized",
        "reconciliation_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, property_name) is False


def test_description_freezes_exact_get_and_capture_identity_without_authority() -> None:
    description = _description()

    assert description.account_id == ACCOUNT_ID
    assert description.capture_idempotency_key == CAPTURE_KEY
    assert str(UUID(description.capture_id)) == description.capture_id
    assert description.capture_id == _description().capture_id
    assert description.method == "GET"
    assert description.base_url == "https://paper-api.alpaca.markets"
    assert description.path == "/v2/positions"
    assert dict(description.query) == {}
    assert description.request_target == "/v2/positions"
    assert len(description.semantic_sha256) == 64
    _assert_no_authority(description)

    mutable: Any = description
    with pytest.raises(FrozenInstanceError):
        mutable.account_id = "different"
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="8-128"):
        create_alpaca_paper_position_snapshot_description(
            account_id=ACCOUNT_ID,
            capture_idempotency_key="short",
        )


def test_raw_first_capture_binds_receipt_and_preserves_exact_decimal_lexemes() -> None:
    recorder = _Recorder()
    body = _body(
        _position(1),
        _position(2, symbol="QQQ", side="short"),
    )

    result = _persist(recorder, body)

    assert recorder.receipts == [result.receipt]
    delivery = result.receipt.delivery
    assert delivery == recorder.deliveries[0]
    assert delivery.account_id == ACCOUNT_ID
    assert delivery.delivery_idempotency_key == CAPTURE_KEY
    assert delivery.provider_id == ALPACA_PAPER_ADAPTER_ID
    assert delivery.adapter_version == ALPACA_PAPER_ADAPTER_VERSION
    assert delivery.environment == "paper"
    assert delivery.channel == ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_CHANNEL
    assert delivery.operation == ALPACA_PAPER_POSITION_SNAPSHOT_INGRESS_OPERATION
    assert delivery.correlation_sha256 == result.observation.description.semantic_sha256
    assert delivery.transport_status == result.observation.http_status == 200
    assert delivery.provider_request_id == result.observation.provider_request_id
    assert delivery.received_at == result.observation.received_at == RECEIVED_AT
    assert delivery.recorded_at == RECORDED_AT
    assert delivery.body == result.observation.response_body == body
    assert delivery.body_sha256 == result.observation.response_sha256
    assert result.capture_id == result.observation.description.capture_id
    assert result.observation.position_count == 2

    long, short = result.observation.positions
    assert type(long) is AlpacaPaperPositionObservation
    assert long.asset_id == str(UUID(int=1))
    assert long.symbol == "SPY"
    assert long.exchange is AlpacaAssetExchange.ARCA
    assert long.asset_class is AlpacaAssetClass.US_EQUITY
    assert long.asset_marginable is True
    assert long.side is AlpacaPaperPositionSide.LONG
    assert long.average_entry_price.raw == "430.1200"
    assert long.average_entry_price.value == Decimal("430.12")
    assert long.quantity.raw == "2.5000"
    assert long.quantity.value == Decimal("2.5")
    assert long.market_value is not None
    assert long.market_value.raw == "1077.80000"
    assert long.cost_basis.raw == "1075.3000"
    assert long.current_price is not None
    assert long.current_price.raw == "431.120000"
    assert long.quantity_available is not None
    assert long.quantity_available.raw == "1.500"
    assert short.side is AlpacaPaperPositionSide.SHORT
    assert short.quantity.raw == "-2.5000"
    assert short.quantity.value == Decimal("-2.5")
    assert long.semantic_sha256 != short.semantic_sha256
    assert len(result.semantic_sha256) == 64
    assert result.observation.additional_reconciliation_required is True
    for value in (long, short, result.observation, result):
        _assert_no_authority(value)


def test_empty_array_is_retained_but_never_claims_snapshot_completeness() -> None:
    recorder = _Recorder()

    result = _persist(recorder, b"[]")

    assert result.observation.positions == ()
    assert result.observation.position_count == 0
    assert result.observation.provider_snapshot_complete is False
    assert result.observation.reconciliation_complete is False
    assert result.observation.canonical_position_fact_authorized is False


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        (lambda value: value.update({"unreviewed": True}), "frozen position profile"),
        (lambda value: value.pop("cost_basis"), "frozen position profile"),
        (lambda value: value.update({"swap_rate": "1.0"}), "frozen position profile"),
        (lambda value: value.update({"prev_swap_rate": None}), "frozen position profile"),
        (lambda value: value.update({"usd": None}), "frozen position profile"),
        (lambda value: value.update({"avg_entry_price": 430.12}), "frozen position profile"),
        (lambda value: value.update({"asset_marginable": None}), "frozen position profile"),
        (lambda value: value.update({"market_value": None}), "frozen position profile"),
        (lambda value: value.update({"unrealized_pl": None}), "frozen position profile"),
        (lambda value: value.update({"current_price": None}), "frozen position profile"),
        (lambda value: value.update({"qty_available": None}), "frozen position profile"),
        (lambda value: value.update({"asset_class": "crypto"}), "frozen position profile"),
        (lambda value: value.update({"exchange": "CRYPTO"}), "frozen position profile"),
        (lambda value: value.update({"qty": "0"}), "frozen position profile"),
        (lambda value: value.update({"side": "short"}), "frozen position profile"),
    ),
)
def test_reviewed_us_equity_wire_profile_fails_closed(
    mutation: Callable[[dict[str, object]], object],
    match: str,
) -> None:
    value = _position(1)
    mutation(value)

    with pytest.raises(AlpacaPaperPositionSnapshotError, match=match):
        decode_alpaca_paper_position_snapshot_response(
            _description(),
            http_status=200,
            provider_request_id="position-request-profile",
            response_body=_body(value),
            received_at=RECEIVED_AT,
        )


def test_qty_available_is_the_only_accepted_optional_position_field() -> None:
    value = _position(1)
    value.pop("qty_available")

    observation = decode_alpaca_paper_position_snapshot_response(
        _description(),
        http_status=200,
        provider_request_id="position-request-without-available",
        response_body=_body(value),
        received_at=RECEIVED_AT,
    )

    assert observation.positions[0].quantity_available is None


def test_duplicate_asset_and_provider_identities_are_rejected() -> None:
    duplicate_asset = _position(1, symbol="QQQ")
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="provider asset ID"):
        decode_alpaca_paper_position_snapshot_response(
            _description(),
            http_status=200,
            provider_request_id="position-request-duplicate-asset",
            response_body=_body(_position(1), duplicate_asset),
            received_at=RECEIVED_AT,
        )

    duplicate_symbol = _position(2)
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="provider identity"):
        decode_alpaca_paper_position_snapshot_response(
            _description(),
            http_status=200,
            provider_request_id="position-request-duplicate-symbol",
            response_body=_body(_position(1), duplicate_symbol),
            received_at=RECEIVED_AT,
        )


def test_item_bound_rejects_the_whole_capture_without_silent_truncation() -> None:
    recorder = _Recorder()
    repeated = [_position(index + 1, symbol=f"S{index}") for index in range(26)]
    positions = [
        {**repeated[index % len(repeated)], "asset_id": str(UUID(int=index + 1))}
        for index in range(ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS + 1)
    ]
    body = _body(*positions)

    with pytest.raises(AlpacaPaperPositionSnapshotError, match="no items were truncated"):
        _persist(recorder, body)

    assert len(recorder.receipts) == 1
    assert recorder.receipts[0].delivery.body == body


@pytest.mark.parametrize(
    "body",
    (
        b'{"not":"an array"}',
        b'[{"asset_id":"first","asset_id":"second"}]',
        b"[NaN]",
        b"\xff",
    ),
)
def test_invalid_json_shapes_are_rejected_after_raw_persistence(body: bytes) -> None:
    recorder = _Recorder()

    with pytest.raises(AlpacaPaperPositionSnapshotError):
        _persist(recorder, body)

    assert len(recorder.receipts) == 1
    assert recorder.receipts[0].delivery.body == body


def test_missing_request_id_and_http_failure_remain_retained_decode_failures() -> None:
    body = _body(_position(1))
    missing_id = _Recorder()
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="missing X-Request-ID"):
        _persist(missing_id, body, request_id=None)
    assert missing_id.receipts[0].delivery.body == body
    assert missing_id.receipts[0].delivery.provider_request_id is None

    http_failure = _Recorder()
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="only HTTP 200"):
        persist_then_decode_alpaca_paper_position_snapshot_response(
            http_failure,
            _description(),
            http_status=503,
            provider_request_id="position-request-503",
            response_body=body,
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )
    assert http_failure.receipts[0].delivery.transport_status == 503
    assert http_failure.receipts[0].delivery.body == body


def test_mismatched_recorder_receipt_fails_before_decoding() -> None:
    class _MismatchedRecorder:
        def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
            return BrokerIngressReceipt(
                delivery=replace(delivery, body=b"different-position-bytes"),
                ingress_sequence=1,
                previous_receipt_sha256=None,
            )

    with pytest.raises(BrokerIngressError, match="different position snapshot bytes"):
        persist_then_decode_alpaca_paper_position_snapshot_response(
            _MismatchedRecorder(),
            _description(),
            http_status=200,
            provider_request_id="position-request-mismatch",
            response_body=b'{"would":"fail decoding"}',
            received_at=RECEIVED_AT,
            recorded_at=RECORDED_AT,
        )


def test_persisted_binding_rejects_every_material_receipt_mutation() -> None:
    result = _persist(_Recorder(), _body(_position(1)))
    mutations = (
        replace(result.receipt.delivery, account_id="different-account"),
        replace(result.receipt.delivery, delivery_idempotency_key="different-capture"),
        replace(result.receipt.delivery, provider_id="different-provider"),
        replace(result.receipt.delivery, adapter_version="different-version"),
        replace(result.receipt.delivery, environment="live"),
        replace(result.receipt.delivery, channel="different-channel"),
        replace(result.receipt.delivery, operation="different-operation"),
        replace(result.receipt.delivery, correlation_sha256="f" * 64),
        replace(result.receipt.delivery, transport_status=201),
        replace(result.receipt.delivery, provider_request_id="different-request"),
        replace(result.receipt.delivery, received_at=RECEIVED_AT - timedelta(seconds=1)),
        replace(result.receipt.delivery, body=b"different-body"),
    )

    for delivery in mutations:
        with pytest.raises(AlpacaPaperPositionSnapshotError, match="raw receipt"):
            PersistedAlpacaPaperPositionSnapshot(
                receipt=BrokerIngressReceipt(
                    delivery=delivery,
                    ingress_sequence=1,
                    previous_receipt_sha256=None,
                ),
                observation=result.observation,
            )


def test_derived_values_are_proof_constructed_and_inputs_are_exact() -> None:
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPositionDecimal("1")
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPositionObservation()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPositionSnapshotObservation()

    with pytest.raises(AlpacaPaperPositionSnapshotError, match="exact bytes"):
        decode_alpaca_paper_position_snapshot_response(
            _description(),
            http_status=200,
            provider_request_id="position-request-not-bytes",
            response_body="[]",  # type: ignore[arg-type]
            received_at=RECEIVED_AT,
        )
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="timezone-aware"):
        decode_alpaca_paper_position_snapshot_response(
            _description(),
            http_status=200,
            provider_request_id="position-request-naive-time",
            response_body=b"[]",
            received_at=RECEIVED_AT.replace(tzinfo=None),
        )
